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


from base64 import b64decode
from json import loads
from requests.exceptions import HTTPError

from . import GnajomAPI, usecache


__all__ = (
    "MojangAPI", "SessionAPI", "StatusAPI",
    "DEFAULT_MOJANG_API_HOST", "DEFAULT_MOJANG_SESSION_HOST",
    "DEFAULT_MOJANG_STATUS_HOST", "DEFAULT_STATISTICS",
    "STATISTIC_MINECRAFT_SOLD", "STATISTIC_PREPAID_MINECRAFT_REDEEMED",
    "STATISTIC_COBALT_SOLD", "STATISTIC_SCROLLS_SOLD", )


DEFAULT_MOJANG_API_HOST = "https://api.mojang.com"
DEFAULT_MOJANG_SESSION_HOST = "https://sessionserver.mojang.com"
DEFAULT_MOJANG_STATUS_HOST = "https://status.mojang.com"


STATISTIC_MINECRAFT_SOLD = "item_sold_minecraft"
STATISTIC_PREPAID_MINECRAFT_REDEEMED = "prepaid_card_redeemed_minecraft"
STATISTIC_COBALT_SOLD = "item_sold_cobalt"
STATISTIC_SCROLLS_SOLD = "item_sold_scrolls"

DEFAULT_STATISTICS = (
    STATISTIC_MINECRAFT_SOLD,
    STATISTIC_PREPAID_MINECRAFT_REDEEMED,
    STATISTIC_COBALT_SOLD,
    STATISTIC_SCROLLS_SOLD, )


class MojangAPI(GnajomAPI):
    """
    A thin wrapper for the the core portion of the Mojang API

    References
    ----------
    * http://wiki.vg/Mojang_API
    """

    def __init__(self, auth, host=DEFAULT_MOJANG_API_HOST,
                 apicache=None, debug_hook=None):

        super().__init__(auth, host, apicache, debug_hook)

        if self.auth.accessToken:
            bearer = "Bearer " + self.auth.accessToken
            self.api.headers["Authorization"] = bearer


    @usecache
    def username_to_uuid(self, username, at_time=None):
        if at_time is None:
            uri = "/users/profiles/minecraft/%s" % username
        else:
            uri = "/users/profiles/minecraft/%s?at=%i" % (username, at_time)

        try:
            return self.api.get(uri)

        except HTTPError as err:
            # 404 is an expected response if we can't find a username
            # with that value.
            if err.response.status_code == 404:
                return None
            else:
                raise


    @usecache
    def uuid_name_history(self, uuid):
        return self.api.get("/user/profiles/%s/names" % uuid)


    @usecache
    def playernames_to_uuids(self, playernames):
        return self.api.post("/profiles/minecraft", list(playernames))


    def change_skin(self, uuid, skin_url, slim=False):

        uri = "/user/profile/%s/skin" % uuid

        payload = {"model": "slim" if slim else "",
                   "url": skin_url}

        return self.api.post_encoded(uri, payload)


    def upload_skin(self, uuid, skin_stream, slim=False,
                    filename="skin.png", content_type="image/png"):

        uri = "/user/profile/%s/skin" % uuid

        payload = {"model": "slim" if slim else "",
                   "file": (filename, skin_stream, content_type)}

        return self.api.put_form(uri, payload)


    def upload_skin_filename(self, uuid, skin_filename, slim=False):
        # TODO: figure out content-type instead of assuming image/png
        with open(skin_filename, "rb") as skin_stream:
            return self.upload_skin(self, uuid, skin_stream, slim,
                                    filename=skin_filename)


    def reset_skin(self, uuid):
        return self.api.delete("/user/profile/%s/skin" % uuid)


    @usecache
    def whoami(self):
        return self.api.get("/user")


    def statistics(self, which=DEFAULT_STATISTICS):
        which = {"metricKeys": list(which)}
        return self.api.post("/orders/statistics", which)


class SessionAPI(GnajomAPI):
    """
    A thin wrapper for the the session portion of the Mojang API

    References
    ----------
    * http://wiki.vg/Mojang_API
    """

    def __init__(self, auth, host=DEFAULT_MOJANG_SESSION_HOST,
                 apicache=None, debug_hook=None):

        super().__init__(auth, host, apicache, debug_hook)

        if self.auth.accessToken:
            bearer = "Bearer " + self.auth.accessToken
            self.api.headers["Authorization"] = bearer


    @usecache
    def profile_info(self, uuid):
        data = self.api.get("/session/minecraft/profile/%s" % uuid)

        if data:
            props = data.get("properties", ())
            for prop in props:
                if prop["name"] == "textures":
                    # since we happen to know that the textures
                    # property is always going to be a base64 encoded
                    # JSON object, let's go ahead and pre-decode it if
                    # it exists
                    val = prop.get("value", "")
                    val = b64decode(val).decode()
                    val = loads(val) if val else dict()
                    prop["value"] = val
                    break

        return data


    def blocked_servers(self):
        return self.api.get("/blockedservers")


class StatusAPI(GnajomAPI):
    """
    A thin wrapper for the the status portion of the Mojang API

    References
    ----------
    * http://wiki.vg/Mojang_API
    """

    def __init__(self, auth, host=DEFAULT_MOJANG_STATUS_HOST,
                 apicache=None, debug_hook=None):

        super().__init__(auth, host, apicache, debug_hook)


    def check(self):
        resp = self.api.get("/check")
        return resp


#
# The end.
