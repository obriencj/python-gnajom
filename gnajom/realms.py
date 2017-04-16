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
gnajom.realms - Python module for working with Realms servers.

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


from . import GnajomAPI, usecache


__all__ = (
    "RealmsAPI",
    "HOST_DESKTOP_REALMS", "HOST_PE_REALMS",
    "DEFAULT_REALMS_HOST", "DEFAULT_REALMS_VERSION", )


HOST_DESKTOP_REALMS = "https://mcoapi.minecraft.net"
HOST_PE_REALMS = "https://peoapi.minecraft.net"

DEFAULT_REALMS_HOST = HOST_DESKTOP_REALMS
DEFAULT_REALMS_VERSION = "1.10.2"


class RealmsAPI(GnajomAPI):
    """
    A thin wrapper for the Mojang Realms API

    References
    ----------
    * http://wiki.vg/Realms_API
    """

    def __init__(self, auth, host=DEFAULT_REALMS_HOST,
                 version=DEFAULT_REALMS_VERSION,
                 apicache=None, debug_hook=None):

        super().__init__(auth, host, apicache, debug_hook)

        # compose the necessary cookies from data in the auth object
        sid = "token:%s:%s" % (auth.accessToken, auth.selectedProfile["id"])
        user = auth.selectedProfile["name"]

        self.api.cookies.set("sid", sid)
        self.api.cookies.set("user", user)
        self.api.cookies.set("version", version)


    @usecache
    def mco_available(self):
        return self.api.get("/mco/available")


    @usecache
    def mco_client_outdated(self):
        return self.api.get("/mco/client/outdated")


    @usecache
    def mco_tos_agree(self):
        return self.api.post("/mco/tos/agreed")


    @usecache
    def realm_list(self):
        """
        List the realms available for the given account auth
        """

        return self.api.get("/worlds")


    @usecache
    def realm_info(self, realm_id):
        """
        Information about a specific realm by ID
        """

        return self.api.get("/worlds/%i" % realm_id)


    def realm_join(self, realm_id):
        """
        Wakes up a realm so that it can be joined, returns a string
        specifying the IP_ADDRESS:PORT of the running server
        """

        return self.api.get("/worlds/%i/join" % realm_id)


    @usecache
    def realm_backups(self, realm_id):
        """
        Show the backups available for the given realm ID
        """

        return self.api.get("/worlds/%i/backups" % realm_id)


    @usecache
    def realm_world_url(self, realm_id, world):
        """
        Show the download URL for the latest world backup for the given
        realm ID
        """

        return self.api.get("/worlds/%i/slot/%i/download" % (realm_id, world))


    @usecache
    def realm_ops_list(self, realm_id):
        return self.api.get("/ops/%i" % realm_id)


    @usecache
    def realm_subscription(self, realm_id):
        return self.api.get("/subscriptions/%i" % realm_id)


#
# The end.
