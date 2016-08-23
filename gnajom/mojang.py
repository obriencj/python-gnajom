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


from gnajom import APIHost
from base64 import b64decode


__all__ = ("MojangAPI", "SessionAPI", "StatusAPI",
           "DEFAULT_MOJANG_API_HOST", "DEFAULT_MOJANG_STESSION_HOST",
           "DEFAULT_MOJANG_STATUS_HOST", "DEFAULT_STATISTICS",
           "STATISTIC_MINECRAFT_SOLD", "STATISTIC_PREPAID_MINECRAFT_REDEEMED",
           "STATISTIC_COBALT_SOLD", "STATISTIC_SCROLLS_SOLD")


DEFAULT_MOJANG_API_HOST = "https://api.mojang.com"
DEFAULT_MOJANG_SESSION_HOST = "https://sessionserver.mojang.com"
DEFAULT_MOJANG_STATUS_HOST = "https://status.mojang.com"


STATISTIC_MINECRAFT_SOLD = "item_sold_minecraft"
STATISTIC_PREPAID_MINECRAFT_REDEEMED = "prepaid_card_redeemed_minecraft"
STATISTIC_COBALT_SOLD = "item_sold_cobalt"
STATISTIC_SCROLLS_SOLD = "item_sold_scrolls"

DEFAULT_STATISTICS = (STATISTIC_MINECRAFT_SOLD,
                      STATISTIC_PREPAID_MINECRAFT_REDEEMED,
                      STATISTIC_COBALT_SOLD,
                      STATISTIC_SCROLLS_SOLD)


class MojangAPI(object):
    """
    A thin wrapper for the the core portion of the Mojang API

    References
    ----------
    * http://wiki.vg/Mojang_API
    """

    def __init__(self, auth, host=DEFAULT_MOJANG_API_HOST):
        self.auth = auth
        self.api = APIHost(host)

        if self.auth.accessToken:
            bearer =  "Bearer " + self.auth.accessToken
            self.api.headers["Authorization"] = bearer


    def username_to_uuid(self, username, at_time=0):
        return self.api.get("/users/profiles/minecraft/%s?at=%i" %
                            (username, at_time))


    def uuid_name_history(self, uuid):
        return self.api.get("/user/profiles/%s/names" % uuid)


    def playernames_to_uuids(self, playernames):
        return self.api.post("/profiles/minecraft", list(playernames))


    def change_skin(self, uuid, model, skin_url):
        pass


    def upload_skin(self, uuid, model, skin_blob):
        pass


    def upload_skin_filename(self, uuid, model, skin_filename):
        pass


    def reset_skin(self, uuid):
        return self.api.delete("/user/profile/%s/skin" % uuid)


    def my_user_info(self):
        return self.api.get("/user")


    def statistics(self, which=DEFAULT_STATISTICS):
        which = {"metricKeys": list(which)}
        return self.api.post("/orders/statistics", which)


class SessionAPI(object):
    """
    A thin wrapper for the the session portion of the Mojang API

    References
    ----------
    * http://wiki.vg/Mojang_API
    """

    def __init__(self, auth, host=DEFAULT_MOJANG_SESSION_HOST):
        self.auth = auth
        self.api = APIHost(host)


    def profile_textures(self, uuid):
        data = self.api.get("/session/minecraft/profile/%s" % uuid)

        if data:
            props = data.get("properties")
            if props:
                val = props.get("value")
                val = b64decode(val)
                val = loads(val)
                props["value"] = val

        return data


    def blocked_servers(self):
        return self.api.get("/blockedservers")


class StatusAPI(object):
    """
    A thin wrapper for the the status portion of the Mojang API

    References
    ----------
    * http://wiki.vg/Mojang_API
    """

    def __init__(self, auth, host=DEFAULT_MOJANG_STATUS_HOST):
        self.auth = auth # unused, maybe useful in the future.
        self.api = APIHost(host)


    def check(self):
        resp = self.api.get("/check")
        return resp


#
# The end.
