# -*- coding: utf-8 -*-
"""FreeIPA Server Class

Author: Peter Pakos <peter.pakos@wandisco.com>

Copyright (C) 2018 WANdisco

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import print_function
import logging
import ldap
import ldap.modlist
import socket
from .freeipauser import FreeIPAUser
from unidecode import unidecode

log = logging.getLogger(__name__)


class FreeIPAServer(object):
    """Define FreeIPA server object"""
    def __init__(self, host, binddn='cn=Directory Manager', bindpw='', timeout=5, tls=True):
        """Initialise object"""
        log.debug('Initialising FreeIPA server %s' % host)
        self._host = host
        self._binddn = binddn
        self._bindpw = bindpw
        self._timeout = timeout
        self._tls = tls
        self._url = 'ldaps://' + host if self._tls else 'ldap://' + host
        self._set_conn()
        self._set_fqdn()
        self._set_hostname_domain()
        self._set_ip()
        self._set_base_dn()
        self._active_users = {}
        self._stage_users = {}
        self._preserved_users = {}
        self._anon_bind = None

    def __repr__(self):
        """String representation of the object"""
        return 'FreeIPAServer(%r)' % self._host

    def _set_conn(self):
        """Establish connection to the server"""
        if self._tls:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        try:
            conn = ldap.initialize(self._url)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, self._timeout)
            conn.simple_bind_s(self._binddn, self._bindpw)
        except Exception as e:
            if hasattr(e, 'message') and 'desc' in e.message:
                msg = e.message['desc']
            else:
                msg = e.args[0]['desc']
            log.critical(msg)
            raise
        log.debug('%s connection established' % ('LDAPS' if self._tls else 'LDAP'))
        self._conn = conn

    @staticmethod
    def _get_ldap_msg(e):
        """Extract LDAP exception message"""
        msg = e
        if hasattr(e, 'message'):
            msg = e.message
            if 'desc' in e.message:
                msg = e.message['desc']
            elif hasattr(e, 'args'):
                msg = e.args[0]['desc']
        return msg

    def _search(self, base, fltr, attrs=None, scope=ldap.SCOPE_SUBTREE):
        """Perform LDAP search"""
        try:
            results = self._conn.search_s(base, scope, fltr, attrs)
        except Exception as e:
            log.exception(self._get_ldap_msg(e))
            results = False
        return results

    def _set_fqdn(self):
        """Get FQDN from LDAP"""
        results = self._search(
            'cn=config',
            '(objectClass=*)',
            ['nsslapd-localhost'],
            scope=ldap.SCOPE_BASE
        )
        if not results and type(results) is not list:
            r = None
        else:
            dn, attrs = results[0]
            r = attrs['nsslapd-localhost'][0].decode('utf-8')
        self._fqdn = r
        log.debug('FQDN: %s' % self._fqdn)

    def _set_hostname_domain(self):
        """Extract hostname and domain"""
        self._hostname, _, self._domain = str(self._fqdn).partition('.')
        log.debug('Hostname: %s, Domain: %s' % (self._hostname, self._domain))

    def _set_ip(self):
        """Resolve FQDN to IP address"""
        self._ip = socket.gethostbyname(self._fqdn)
        log.debug('IP: %s' % self._ip)

    def _set_base_dn(self):
        """Get Base DN from LDAP"""
        results = self._search(
            'cn=config',
            '(objectClass=*)',
            ['nsslapd-defaultnamingcontext'],
            scope=ldap.SCOPE_BASE
        )
        if results and type(results) is list:
            dn, attrs = results[0]
            r = attrs['nsslapd-defaultnamingcontext'][0].decode('utf-8')
        else:
            raise Exception
        self._base_dn = r
        self._active_user_base = 'cn=users,cn=accounts,' + self._base_dn
        self._stage_user_base = 'cn=staged users,cn=accounts,cn=provisioning,' + self._base_dn
        self._preserved_user_base = 'cn=deleted users,cn=accounts,cn=provisioning,' + self._base_dn
        self._groups_base = 'cn=groups,cn=accounts,' + self._base_dn
        log.debug('Base DN: %s' % self._base_dn)

    def users(self, user_base='active'):
        """Return dict of users"""
        if not getattr(self, '_%s_users' % user_base):
            self._get_users(user_base)
        return getattr(self, '_%s_users' % user_base)

    def _get_users(self, user_base):
        """"Get users from LDAP"""
        results = self._search(
            getattr(self, '_%s_user_base' % user_base),
            '(objectClass=*)',
            ['*'],
            scope=ldap.SCOPE_ONELEVEL
        )
        for dn, attrs in results:
            uid = attrs.get('uid')[0].decode('utf-8', 'ignore')
            getattr(self, '_%s_users' % user_base)[uid] = FreeIPAUser(dn, attrs)
            # print(attrs)
        log.debug('%s users: %s' % (user_base.capitalize(), len(getattr(self, '_%s_users' % user_base))))

    def find_users_by_email(self, email, user_base='active'):
        """Return list of users with given email address"""
        users = []
        for user in getattr(self, 'users')(user_base).values():
            mail = user.mail
            if mail and email in mail:
                users.append(user)
        log.debug('%s users with email address %s: %s' % (user_base.capitalize(), email, len(users)))
        return users

    def count_users(self, user_base='active'):
        """Return users count"""
        return len(self.users(user_base))

    def _get_anon_bind(self):
        """Check anonymous bind
        :return: 'on', 'off', 'rootdse' or None
        """
        r = self._search(
            'cn=config',
            '(objectClass=*)',
            ['nsslapd-allow-anonymous-access'],
            scope=ldap.SCOPE_BASE
        )
        dn, attrs = r[0]
        state = attrs.get('nsslapd-allow-anonymous-access')[0].decode('utf-8', 'ignore')
        if state in ['on', 'off', 'rootdse']:
            r = state
        else:
            r = None
        self._anon_bind = r

    @property
    def anon_bind(self):
        if not self._anon_bind:
            self._get_anon_bind()
        return self._anon_bind

    def add_user(self, uid, employee_number, given_name, sn, department_number, title, mobile, mail, ou, gid='-1'):
        try:
            uid = uid.decode('utf8')
        except AttributeError:
            pass
        uid = unidecode(uid)
        dn = 'uid=%s,%s' % (uid, self._stage_user_base)
        attrs = dict()
        attrs['objectclass'] = [b'top', b'posixaccount', b'person', b'inetorgperson', b'organizationalperson']
        attrs['cn'] = ('%s %s' % (given_name, sn)).encode('utf8')
        attrs['givenName'] = given_name.encode('utf8')
        attrs['sn'] = sn.encode('utf8')
        attrs['uid'] = uid.encode('utf8')
        attrs['uidNumber'] = '-1'.encode('utf8')
        attrs['gidNumber'] = gid.encode('utf8')
        attrs['title'] = title.encode('utf8') if title else ''
        attrs['mobile'] = mobile.encode('utf8') if mobile else ''
        attrs['telephoneNumber'] = mobile.encode('utf8') if mobile else ''
        attrs['mail'] = mail.encode('utf8') if mail else ''
        attrs['homeDirectory'] = ('/home/%s' % uid).encode('utf8')
        attrs['loginShell'] = '/usr/sbin/nologin'.encode('utf8')
        attrs['employeeNumber'] = employee_number.encode('utf8') if employee_number else ''
        attrs['departmentNumber'] = department_number.encode('utf8') if department_number else ''
        attrs['ou'] = ou.encode('utf8') if ou else ''
        ldif = ldap.modlist.addModlist(attrs)
        try:
            self._conn.add_s(dn, ldif)
        except ldap.LDAPError as e:
            log.error('Failed to add user %s: %s' % (uid, self._get_ldap_msg(e)))
            return False
        log.debug('Added user %s' % uid)
        return True

    def modify(self, dn, attr, old_value, new_value):
        old_value = '' if not old_value else [old_value.encode('utf8')]
        new_value = '' if not new_value else [new_value.encode('utf8')]
        old = {attr: old_value}
        new = {attr: new_value}
        ldif = ldap.modlist.modifyModlist(old, new)

        try:
            self._conn.modify_s(dn, ldif)
        except ldap.LDAPError:
            return False

        return True
