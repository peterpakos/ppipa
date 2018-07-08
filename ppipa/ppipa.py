#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""PP's FreeIPA Module

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

from __future__ import absolute_import, print_function
import logging
import ldap
import socket


class FreeIPAServer(object):
    def __init__(self, host, binddn='cn=Directory Manager', bindpw='', timeout=5, tls=True):
        self._log = logging.getLogger(__name__)
        self._log.debug('Initialising FreeIPA server %s' % host)
        self._host = host
        self._binddn = binddn
        self._bindpw = bindpw
        self._timeout = timeout
        self._tls = tls
        self._url = 'ldaps://' + host if self._tls else 'ldap://' + host
        self._conn = self._get_conn()
        self._fqdn = self._get_fqdn()
        self._hostname, _, self._domain = str(self._fqdn).partition('.')
        self._ip = self._get_ip()
        self._log.debug('Hostname: %s, Domain: %s, IP: %s' % (self._hostname, self._domain, self._ip))

    def _get_conn(self):
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
            self._log.critical(msg)
            raise

        self._log.debug('%s connection established' % ('LDAPS' if self._tls else 'LDAP'))
        return conn

    @staticmethod
    def _get_ldap_msg(e):
        msg = e
        if hasattr(e, 'message'):
            msg = e.message
            if 'desc' in e.message:
                msg = e.message['desc']
            elif hasattr(e, 'args'):
                msg = e.args[0]['desc']
        return msg

    def _search(self, base, fltr, attrs=None, scope=ldap.SCOPE_SUBTREE):
        try:
            results = self._conn.search_s(base, scope, fltr, attrs)
        except Exception as e:
            self._log.exception(self._get_ldap_msg(e))
            results = False
        return results

    def _get_fqdn(self):
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

        return r

    def _get_ip(self):
        return socket.gethostbyname(self._fqdn)
