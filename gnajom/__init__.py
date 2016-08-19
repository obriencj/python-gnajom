# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see
# <http://www.gnu.org/licenses/>.


"""
gnajom - Python package for working with Mojang API services.

The core package provides utilities to ease in constucting the individual
sevirces such as auth, realms, and users.

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


from json import load, dump, dumps
from requests import get, post
from requests.cookies import RequestsCookieJar
from requests.exceptions import HTTPError


__all__ = ( "ApiHelper", )


class ApiHelper(object):
    """
    Lightweight wrapper for JSON via GET and POST calls
    """

    def __init__(self, hosturi):
        self._host = hosturi
        self.cookies = RequestsCookieJar()


    def get(self, endpoint):
        resp = get(self._host + endpoint, cookies=self.cookies)

        resp.raise_for_status()

        if len(resp.content):
            return resp.json()
        else:
            return None


    def post(self, endpoint, payload):
        data = dumps(payload)
        resp = post(self._host + endpoint, data, cookies=self.cookies)

        resp.raise_for_status()

        if len(resp.content):
            return resp.json()
        else:
            return None


#
# The end.
