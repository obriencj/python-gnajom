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


from json import dumps
from optparse import OptionParser, OptionGroup
from os.path import expanduser
from requests import post
from requests.exceptions import HTTPError
from uuid import uuid1

import sys


__all__ = ( "ApiObject", "Authentication",
            "cli", "cli_options", "cli_auth_optgroup",
            "cli_do_authenticate", "cli_do_refresh",
            "cli_do_validate", "cli_do_invalidate",
            "cli_do_signoff",
            "main" )


HOST_YGGDRASIL = "https://authserver.mojang.com"


MINECRAFT_AGENT_V1 = {
    "name": "Minecraft",
    "version": 1,
}


DEFAULT_CONFIG = expanduser("~/.gnajom")


_cmd_help = """
The following commands are supported:
  help          print this message
  authenticate  creates a new CLI session
  refresh       refresh the lease on the existing CLI session
  validate      check that the CLI session is still valid
  invalidate    invalidate the existing key for this CLI session
  signout       invalidate all sessions for the given user
"""


class ApiObject(object):
    """
    Lightweight wrapper for JSON via POST
    """

    def __init__(self, hosturi):
        self._host = hosturi


    def post(self, endpoint, payload):
        data = dumps(payload)
        resp = post(self._host + endpoint, data)
        resp.raise_for_status()
        return resp.json()


class Authentication(ApiObject):
    """
    A thin wrapper for the Mojang authentiation scheme, 'Yggdrasil'

    References
    ----------
    * http://wiki.vg/Authentication
    """

    def __init__(self, username, clientToken=None, accessToken=None,
                 authhost=HOST_YGGDRASIL, agent=MINECRAFT_AGENT_V1):

        self.api = ApiObject(authhost)
        self.username = username
        self.agent = agent
        self.clientToken = None
        self.accessToken = None
        self.profile = None


    def authenticate(self, password):
        payload = { "username": self.username,
                    "password": password, }

        if self.agent:
            payload["agent"] = self.agent

        if self.clientToken:
            payload["clientToken"] = self.clientToken

        ret = self.api.post("/authenticate", payload)

        self.clientToken = ret["clientToken"]
        self.accessToken = ret["accessToken"]
        self.profile = ret["selectedProfile"]


    def refresh(self):
        payload = { "accessToken": self.accessToken,
                    "clientToken": self.clientToken,
                    "selectedProfile": self.profile, }

        ret = self.api.post("/refresh", payload)


    def validate(self):
        payload = { "accessToken": self.accessToken, }

        ret = self.api.post("/validate", payload)


    def signout(self, password):
        payload = { "username": self.username,
                    "password": password, }

        ret = self.api.post("/signout", payload)


    def invalidate(self):
        payload = { "accessToken": self.accessToken,
                    "clientToken": self.clientToken, }

        ret = self.api.post("/invalidate", payload)


def gen_clientToken():
    """
    Generate a random clientToken string via UUID
    """

    return uuid.uuid1().bytes.encode("hex")


def cli_do_authenticate(parser, options, *args):
    pass


def cli_do_refresh(parser, options, *args):
    pass


def cli_do_validate(parser, options, *args):
    pass


def cli_do_signout(parser, options, *args):
    pass


def cli_do_invalidate(parser, options, *args):
    pass


def cli_help_commands(_parser, _options, *_args):
    print _cmd_help
    return 0


_COMMANDS = {
    "help": cli_help_commands,
    "authenticate": cli_do_authenticate,
    "refresh": cli_do_refresh,
    "validate": cli_do_validate,
    "signout": cli_do_signout,
    "invalidate": cli_do_invalidate,
}


def cli(parser, options, args):
    if options.help_commands:
        return cli_help_commands(parser, options)

    if len(args) < 2:
        parser.error("No command specified." + _cmd_help)

    cmd = args[1].lower()
    if cmd not in _COMMANDS:
        parser.error("Invalid command: %s%s" % (cmd, _cmd_help))

    else:
        _COMMANDS[cmd](parser, options, *args)


def cli_optparser():
    p = OptionParser("%prog COMMAND [options]")
    p.add_option_group(cli_auth_optgroup(p))
    p.add_option("--help-commands", action="store_true", default=False,
                 help="list available commands")
    return p


def cli_auth_optgroup(parser):
    g = OptionGroup(parser, "Authentication Options")

    g.add_option("-c", "--config", action="store", default=DEFAULT_CONFIG,
                 help="Configuration file to use")
    g.add_option("-r", "--profile", action="store", default=None,
                 help="Login profile to use")
    g.add_option("-u", "--username", action="store", default=None,
                 help="Mojang account user")
    g.add_option("-p", "--password", action="store", default=None,
                 help="Mojang account password")
    g.add_option("-a", "--auth-host", action="store", default=None,
                 help="Mojang authentication host")

    return g


def main_cli():
    parser = cli_optparser()
    try:
        return cli(parser, *parser.parse_args(sys.argv))
    except KeyboardInterrupt:
        print >> sys.stderr
        return 130
    except HTTPError as he:
        print >> sys.stderr, he
        return -1


#
# The end.
