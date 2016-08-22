# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see
# <http://www.gnu.org/licenses/>.


"""
gnajom.mojang - The core mojang API for users, profiles, skins,
and service status

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


from gnajom import ApiHelper


DEFAULT_MOJANG_API_HOST = "https://api.mojang.com"
DEFAULT_MOJANG_SESSION_HOST = "https://sessionserver.mojang.com"
DEFAULT_MOJANG_STATUS_HOST = "https://status.mojang.com"


class MojangAPI(object):
    """
    A thin wrapper for the the core portion of the Mojang API

    References
    ----------
    * http://wiki.vg/Mojang_API
    """

    def __init__(self, auth, host=DEFAULT_MOJANG_API_HOST):
        self.auth = auth
        self.api = ApiObject(host)


    def username_to_uuid(self, username, at_time=0):
        return self.api.get("/users/profiles/minecraft/%s?at=%i" %
                            (username, at_time))


    def uuid_name_history(self, uuid):
        return self.api.get("/user/profiles/%s/names" % uuid)


    def playernames_to_uuid(self, playernames):
        return self.api.post("/profiles/minecraft", list(playernames))


class SessionAPI(object):
    """
    A thin wrapper for the the session portion of the Mojang API

    References
    ----------
    * http://wiki.vg/Mojang_API
    """

    def __init__(self, auth, host=DEFAULT_MOJANG_SESSION_HOST):
        self.auth = auth
        self.api = ApiObject(host)


class StatusAPI(object):
    """
    A thin wrapper for the the status portion of the Mojang API

    References
    ----------
    * http://wiki.vg/Mojang_API
    """

    def __init__(self, auth=None, host=DEFAULT_MOJANG_STATUS_HOST):
        self.auth = auth
        self.api = ApiObject(host)


    def check(self):
        resp = self.api.get("/check")
        return resp


#
# The end.
