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

from __future__ import absolute_import, print_function
import logging

log = logging.getLogger(__name__)


class FreeIPAUser(object):
    """FreeIPA User Class"""
    def __init__(self, dn, attrs):
        """Initialise object"""
        self._dn = dn
        self._attrs = attrs

    @property
    def dn(self):
        return self._dn

    @property
    def uid(self):
        return self._get('uid')

    @property
    def given_name(self):
        return self._get('givenName')

    @property
    def sn(self):
        return self._get('sn')

    @property
    def mail(self):
        return self._get('mail')

    @property
    def title(self):
        return self._get('title')

    @property
    def home_directory(self):
        return self._get('homeDirectory')

    @property
    def cn(self):
        return self._get('cn')

    @property
    def uid_number(self):
        return self._get('uidNumber')

    @property
    def gid_number(self):
        return self._get('gidNumber')

    @property
    def login_shell(self):
        return self._get('loginShell')

    @property
    def object_class(self):
        return self._get('objectClass')

    def _get(self, attr):
        """Return user's attribute/attributes"""
        a = self._attrs.get(attr)
        if not a:
            return []
        if type(a) is list:
            r = [i.decode('utf-8', 'ignore') for i in a]
        else:
            r = [a.decode('utf-8', 'ignore')]
        return r
