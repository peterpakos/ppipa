# -*- coding: utf-8 -*-
"""FreeIPA User Class

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

log = logging.getLogger(__name__)


class FreeIPAUser(object):
    """FreeIPA User Class"""
    def __init__(self, dn, attrs):
        """Initialise object"""
        self._dn = dn
        self._attrs = attrs
        self._base_dn = str(dn).partition('cn=users,cn=accounts,')[2]

    def __repr__(self):
        return 'FreeIPAUser(%r)' % self._dn

    @property
    def dn(self):
        return self._dn

    @property
    def uid(self):
        return self._get_attr('uid')

    @property
    def given_name(self):
        return self._get_attr('givenName')

    @property
    def sn(self):
        return self._get_attr('sn')

    @property
    def cn(self):
        return self._get_attr('cn')

    @property
    def title(self):
        return self._get_attr('title')

    @property
    def home_directory(self):
        return self._get_attr('homeDirectory')

    @property
    def uid_number(self):
        return self._get_attr('uidNumber')

    @property
    def gid_number(self):
        return self._get_attr('gidNumber')

    @property
    def login_shell(self):
        return self._get_attr('loginShell')

    @property
    def employee_number(self):
        return self._get_attr('employeeNumber')

    @property
    def department_number(self):
        return self._get_attr('departmentNumber')

    @property
    def ou(self):
        return self._get_attr('ou')

    @property
    def mail(self):
        return self._get_attr_list('mail')

    @property
    def mobile(self):
        return self._get_attr_list('mobile')

    @property
    def telephone_number(self):
        return self._get_attr_list('telephoneNumber')

    @property
    def object_class(self):
        return self._get_attr_list('objectClass')

    @property
    def member_of(self):
        return self._get_attr_list('memberOf')

    def is_member_of(self, group_name):
        """Return True if member of LDAP group, otherwise return False"""
        group_dn = 'cn=%s,cn=groups,cn=accounts,%s' % (group_name, self._base_dn)
        if str(group_dn).lower() in [str(i).lower() for i in self.member_of]:
            return True
        else:
            return False

    def _get_attr_list(self, attr):
        """Return user's attribute/attributes"""
        a = self._attrs.get(attr)
        if not a:
            return []
        if type(a) is list:
            r = [i.decode('utf-8', 'ignore') for i in a]
        else:
            r = [a.decode('utf-8', 'ignore')]
        return r

    def _get_attr(self, x):
        y = self._get_attr_list(x)
        r = y[0] if type(y) is list and len(y) > 0 else None
        return r
