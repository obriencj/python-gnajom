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


# seriously, how did people get along before requests? it's a shining
# gem among all python modules. get, put, cookies, headers, multi-part
# form encoding, url form encoding, all easily accessible.


__all__ = ( "APIHost", )


class APIHost(object):
    """
    Lightweight wrapper for JSON via GET and POST calls
    """

    def __init__(self, hosturi):

        # if an empty hosturi has gotten this far in the API,
        # something is screwed up.
        assert(hosturi)

        self._host = hosturi
        self.cookies = RequestsCookieJar()
        self.headers = {}


    def get(self, endpoint):
        """
        Trigger an API endpoint on the host via an HTTP GET. Any JSON
        results will be parsed and returned.
        """

        assert(endpoint)

        resp = get(self._host + endpoint,
                   cookies=self.cookies, headers=self.headers)

        resp.raise_for_status()

        if len(resp.content):
            return resp.json()
        else:
            return None


    def delete(self, endpoint):
        """
        Trigger an API endpoint on the host via an HTTP DELETE. Any JSON
        results will be parsed and returned.
        """

        assert(endpoint)

        resp = delete(self._host + endpoint,
                      cookies=self.cookies, headers=self.headers)

        resp.raise_for_status()

        if len(resp.content):
            return resp.json()
        else:
            return None


    def post(self, endpoint, payload):
        """
        Trigger an API endpoint on the host via an HTTP POST, sending
        payload represented as a JSON. Any JSON results will be parsed
        and returned.
        """

        assert(endpoint)

        data = dumps(payload)

        headers = self.headers.copy()
        headers["Content-Type"] = "application/json"

        resp = post(self._host + endpoint, data,
                    cookies=self.cookies, headers=self.headers)

        resp.raise_for_status()

        if len(resp.content):
            return resp.json()
        else:
            return None


    def post_form(self, endpoint, payload):
        """
        Trigger an API endpoint on the host via an HTTP POST, sending
        payload represented as multipart form data. Any JSON results
        will be parsed and returned.
        """

        assert(endpoint)

        # requests is smart enough to update the Content-Type header
        # when the files= argument is specified
        resp = post(self._host + endpoint, files=payload,
                    cookies=self.cookies, headers=self.headers)

        resp.raise_for_status()

        if len(resp.content):
            return resp.json()
        else:
            return None


    def post_encoded(self, endpoint, payload):
        """
        Trigger an API endpoint on the host via an HTTP POST, sending
        payload represented as urlencoded form data. And JSON results
        will be parsed and returned.
        """

        assert(endpoint)

        data = urlencode(payload)

        headers = self.headers.copy()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        resp = post(self._host + endpoint, data,
                    cookies=self.cookies, headers=self.headers)

        resp.raise_for_status()

        if len(resp.content):
            return resp.json()
        else:
            return None



#
# The end.
