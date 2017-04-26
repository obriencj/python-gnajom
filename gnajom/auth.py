# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see
# <http://www.gnu.org/licenses/>.


"""
gnajom.auth - Python module for working with Yggdrasil, Mojang's
authentication system.

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


from json import dump, load
from requests.exceptions import HTTPError
from uuid import uuid1

from . import APIHost


__all__ = (
    "Authentication", "auth_from_file", "generate_clientToken",
    "HOST_YGGDRASIL", "DEFAULT_AUTH_HOST", "MINECRAFT_AGENT_V1",
    "GNAJOM_CLIENT_TOKEN", )


HOST_YGGDRASIL = "https://authserver.mojang.com"

DEFAULT_AUTH_HOST = HOST_YGGDRASIL

MINECRAFT_AGENT_V1 = {
    "name": "Minecraft",
    "version": 1,
}

GNAJOM_CLIENT_TOKEN = "python-gnajom.preoccupied.net"


class Authentication(object):
    """
    A thin wrapper for the Mojang authentiation scheme, 'Yggdrasil'

    References
    ----------
    * http://wiki.vg/Authentication
    """

    def __init__(self, username, clientToken=GNAJOM_CLIENT_TOKEN,
                 accessToken=None,
                 host=HOST_YGGDRASIL, agent=MINECRAFT_AGENT_V1):

        self.api = APIHost(host)
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

        payload = {"username": self.username,
                   "password": password,
                   "requestUser": True, }

        if self.agent:
            payload["agent"] = self.agent

        if self.clientToken:
            payload["clientToken"] = self.clientToken

        try:
            ret = self.api.post("/authenticate", payload)

        except HTTPError as err:
            # if it's just a 403, that means the auth was wrong, so
            # it's simple failure. Any other kind of error is a
            # different kind of problem, so we'll propagate it up.

            if err.response.status_code == 403:
                return False
            else:
                raise

        else:
            self.clientToken = ret["clientToken"]
            self.accessToken = ret["accessToken"]
            self.selectedProfile = ret.get("selectedProfile")
            self.user = ret.get("user")

            return True


    def refresh(self):
        """
        ensure that this session remains valid. May result in a new
        accessToken.
        """

        payload = {"accessToken": self.accessToken,
                   "clientToken": self.clientToken,
                   "requestUser": True, }

        try:
            ret = self.api.post("/refresh", payload)

        except HTTPError as err:
            # a 403 just means the session was completely invalid,
            # which is expected behavior in many circumstances. In
            # that case, we just return False. Any other error gets
            # propagated up.

            if err.response.status_code == 403:
                return False
            else:
                raise

        else:
            self.clientToken = ret["clientToken"]
            self.accessToken = ret["accessToken"]
            self.selectedProfile = ret.get("selectedProfile")
            self.user = ret.get("user")

            return True


    def validate(self):
        """
        check that the session is currently valid, and can be used to
        perform other actions. An invalid session will need to be
        renewed or a full re-auth may be required.
        """

        if not self.accessToken:
            return False

        payload = {"accessToken": self.accessToken, }

        try:
            self.api.post("/validate", payload)

        except HTTPError as err:
            # one again, 403 is an expected possibility. Everything
            # else is wonky.

            if err.response.status_code == 403:
                return False
            else:
                raise

        else:
            return True


    def signout(self, password):
        """
        invalidates all sessions against the specified account
        """

        payload = {"username": self.username,
                   "password": password, }

        try:
            self.api.post("/signout", payload)

        except HTTPError as err:
            # 403 means bad username/password in this case
            if err.response.status_code == 403:
                return False
            else:
                raise

        else:
            return True


    def invalidate(self):
        """
        invalidates the current session
        """

        if not self.accessToken:
            return None

        payload = {"accessToken": self.accessToken,
                   "clientToken": self.clientToken, }

        # even if we're already invalidated, this won't raise an
        # HTTPError, so we won't try to filter out a 403
        self.api.post("/invalidate", payload)

        self.accessToken = None
        return True


    def load(self, filename):
        """
        set the state of this session to the what is represented in the
        JSON data stored in filename. Errors (access, malformed JSON,
        etc) while loading will be propagated.
        """

        with open(filename) as fd:
            session = load(fd)

        if "host" in session:
            host = session.pop("host")
            self.api = APIHost(host)

        self.__dict__.update(session)


    def save(self, filename):
        """
        save the state of this session to JSON data and write it to
        filename
        """

        with open(filename, "w") as fd:
            self.write(fd)


    def write(self, stream):
        session = dict(self.__dict__)
        session["host"] = self.api._host
        del session["api"]

        dump(session, stream)


    def ensureClientToken(self):
        """
        generate a clientToken for this session if one doesn't already
        exist
        """

        if not self.clientToken:
            self.clientToken = generate_clientToken()


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

    return uuid1().hex


#
# The end.
