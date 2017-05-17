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


from . import GnajomAPI

from requests import get, post


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


    def mco_available(self):
        return self.api.get("/mco/available")


    def mco_client_outdated(self):
        return self.api.get("/mco/client/outdated")


    def mco_tos_agree(self):
        return self.api.post("/mco/tos/agreed")


    def realm_list(self):
        """
        List the realms available for the given account auth
        """

        return self.api.get("/worlds")


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


    def realm_backups(self, realm_id):
        """
        Show the backups available for the given realm ID
        """

        return self.api.get("/worlds/%i/backups" % realm_id)


    def realm_world_select(self, realm_id, world):
        """
        Sets the active world for the given realm ID
        """

        uri = "/worlds/%i/slot/%i" % (realm_id, world)

        return self.api.put(uri)


    def realm_upload_endpoint(self, realm_id):
        """
        Fetch the endpoint and token for uploading a world backup into a
        realm
        """

        uri = "/worlds/%i/backups/upload" % realm_id

        payload = {"token": "",
                   "uploadEndpoint": "",
                   "worldClosed": False}

        return self.api.put(uri, payload)


    def realm_world_upload_filename(self, realm_id, world,
                                    world_gz_filename):

        """
        upload a minecraft world wrapped up in a tar.gz file to a world
        on a given realm
        """

        with open(world_gz_filename, "rb") as gz:
            return self.realm_world_upload(self, realm_id, world, gz)


    def realm_world_upload(self, realm_id, world, world_gz_stream):
        """
        upload a minecraft world as a tar.gz stream to a world on a given
        realm
        """

        info = self.realm_upload_endpoint(realm_id)
        host = info["uploadEndpoint"]
        port = info["port"]
        token = info["token"]

        return self._endpoint_upload(realm_id, world, host, port,
                                     token, world_gz_stream)


    def _endpoint_upload(self, realm_id, world,
                         host, port, token, gz_stream):

        uri = "http://%s:%s/upload/%i/%i" % (host, port, realm_id, world)

        cookies = self.api.cookies.copy()
        cookies["token"] = token

        headers = self.api.headers.copy()
        headers["Content-Type"] = "application/octet-stream"

        resp = post(uri, data=iter(gz_stream),
                    cookies=cookies, headers=headers)

        resp.raise_for_status()

        return resp.json() if len(resp.content) else None


    def realm_world_download(self, realm_id, world, filename):

        url = self.realm_world_url(realm_id, world)
        dl = url.get("downloadLink")

        if not url:
            return None

        total_size = 0
        resp = get(dl, stream=True)
        with open(filename, "wb") as out:
            for chunk in resp.iter_content(chunk_size=2**20):
                out.write(chunk)
                total_size += len(chunk)

        return total_size


    def realm_world_url(self, realm_id, world):
        """
        Show the download URL for the latest world backup for the given
        realm ID.

        NOTE: seems to currently be bugged -- no matter what world you
        specify, it always downloads the currently active world.
        """

        uri = "/worlds/%i/slot/%i/download" % (realm_id, world)

        return self.api.get(uri)


    def realm_reset(self, realm_id,
                    structures=True, level=0, seed="", template=-1):

        uri = "/worlds/%i/reset" % realm_id

        payload = {"generateStructures": structures,
                   "levelType": level,
                   "seed": seed or "",
                   "worldTemplateId": template}

        return self.api.post(uri, payload)


    def realm_ops_list(self, realm_id):
        return self.api.get("/ops/%i" % realm_id)


    def realm_subscription(self, realm_id):
        return self.api.get("/subscriptions/%i" % realm_id)


#
# The end.
