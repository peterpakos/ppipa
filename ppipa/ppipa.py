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
    def __init__(self, host, bindpw, binddn='cn=Directory Manager', timeout=5):
        self._log = logging.getLogger(__name__)
        self._log.debug('Initialising FreeIPA server %s' % host)
        self._binddn = binddn
        self._bindpw = bindpw
        self._timeout = timeout

        try:
            ip = socket.gethostbyname(host)

            if ip == host:
                self._ip = ip
                self._hostname = socket.gethostbyaddr(self._ip)[0]
            else:
                self._ip = socket.gethostbyname(host)
                self._hostname = host
        except Exception as e:
            self._log.critical(e)
            raise

        self._url = 'ldaps://' + self._hostname
        self._log.debug('URL: %s (IP: %s)' % (self._url, self._ip))

        self._conn = self._get_conn()

    def _get_conn(self):
        self._log.debug('Setting up LDAP connection')
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        try:
            conn = ldap.initialize(self._url)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, self._timeout)
            conn.simple_bind_s(self._binddn, self._bindpw)
        except (
            ldap.SERVER_DOWN,
            ldap.NO_SUCH_OBJECT,
            ldap.INVALID_CREDENTIALS
        ) as e:
            if hasattr(e, 'message') and 'desc' in e.message:
                msg = e.message['desc']
            else:
                msg = e.args[0]['desc']
            self._log.debug('%s (%s)' % (msg, self._url))
            return False

        self._log.debug('LDAP connection established')
        return conn
