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

The core module focuses on interacting with Yggdrasil, Mojang's
authentication system.

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


from json import load, dump, dumps
from requests import get, post
from requests.cookies import RequestsCookieJar
from requests.exceptions import HTTPError
from uuid import uuid1


__all__ = ( "ApiHelper", "Authentication",
            "auth_from_file", "generate_clientToken",
            "HOST_YGGDRASIL", "DEFAULT_AUTH_HOST",
            "MINECRAFT_AGENT_V1" )


HOST_YGGDRASIL = "https://authserver.mojang.com"

DEFAULT_AUTH_HOST = HOST_YGGDRASIL

MINECRAFT_AGENT_V1 = {
    "name": "Minecraft",
    "version": 1,
}


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


class Authentication(object):
    """
    A thin wrapper for the Mojang authentiation scheme, 'Yggdrasil'

    References
    ----------
    * http://wiki.vg/Authentication
    """

    def __init__(self, username, clientToken=None, accessToken=None,
                 host=HOST_YGGDRASIL, agent=MINECRAFT_AGENT_V1):

        self.api = ApiHelper(host)
        self.username = username
        self.user = None
        self.agent = agent
        self.clientToken = clientToken
        self.accessToken = accessToken
        self.selectedProfile = None


    def authenticate(self, password):
        """
        generate an accessToken for this session
        """

        payload = { "username": self.username,
                    "password": password,
                    "requestUser": True }

        if self.agent:
            payload["agent"] = self.agent

        if self.clientToken:
            payload["clientToken"] = self.clientToken

        ret = self.api.post("/authenticate", payload)

        self.clientToken = ret["clientToken"]
        self.accessToken = ret["accessToken"]
        self.selectedProfile = ret.get("selectedProfile")
        self.user = ret.get("user")


    def refresh(self):
        """
        ensure that this session remains valid. May result in a new
        accessToken.
        """

        payload = { "accessToken": self.accessToken,
                    "clientToken": self.clientToken,
                    "requestUser": True }

        ret = self.api.post("/refresh", payload)

        self.clientToken = ret["clientToken"]
        self.accessToken = ret["accessToken"]
        self.selectedProfile = ret.get("selectedProfile")
        self.user = ret.get("user")


    def validate(self):
        """
        check that the session is currently valid, and can be used to
        perform other actions. An invalid session will need to be
        renewed or a full re-auth may be required.
        """

        payload = { "accessToken": self.accessToken, }

        ret = self.api.post("/validate", payload)


    def signout(self, password):
        """
        invalidates all sessions against the specified account
        """

        payload = { "username": self.username,
                    "password": password, }

        ret = self.api.post("/signout", payload)


    def invalidate(self):
        """
        invalidates the current session
        """

        payload = { "accessToken": self.accessToken,
                    "clientToken": self.clientToken, }

        ret = self.api.post("/invalidate", payload)


    def load(self, filename):
        """
        set the state of this session to the what is represented in the
        JSON data stored in filename
        """

        with open(filename) as fd:
            session = load(fd)

        if "host" in session:
            host = session.pop("host")
            self.api = ApiHelper(host)

        self.__dict__.update(session)


    def save(self, filename):
        """
        save the state of this session to JSON data and write it to
        filename
        """

        session = dict(self.__dict__)
        session["host"] = self.api._host
        del session["api"]

        with open(filename, "w") as fd:
            dump(session, fd)


def auth_from_file(filename):
    """
    return an Authentication instance loaded from a file
    """

    auth = Authentication(None)
    auth.load(filename)
    return auth


def generate_clientToken():
    """
    Generate a random clientToken string via UUID
    """

    return uuid.uuid1().bytes.encode("hex")


#
# The end.
