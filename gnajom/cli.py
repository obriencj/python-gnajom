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
gnajom.cli - Module with command-line features for gnajom.
Provides access to various aspects of the APIs via a nested
sub-command system.

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


import requests
import sys

from argparse import ArgumentParser
from getpass import getpass
from os import chmod, makedirs
from os.path import basename, exists, expanduser, split
from ConfigParser import SafeConfigParser

from .auth import Authentication, DEFAULT_AUTH_HOST
from .realms import RealmsAPI, DEFAULT_REALMS_HOST, DEFAULT_REALMS_VERSION


DEFAULT_CONFIG_FILE = expanduser("~/.gnajom/gnajom.conf")
DEFAULT_SESSION_FILE = expanduser("~/.gnajom/session")


DEFAULTS = {
    "user": None,
    "config_file": DEFAULT_CONFIG_FILE,
    "session_file": DEFAULT_SESSION_FILE,
    "auth_host": DEFAULT_AUTH_HOST,
    "realms_host": DEFAULT_REALMS_HOST,
    "realms_version": DEFAULT_REALMS_VERSION,
}


# --- gnajom auth commands ---


def load_auth(options):
    auth = Authentication(options.user, host=options.auth_host)

    session = options.session_file or DEFAULT_SESSION_FILE
    if exists(session):
        auth.load(session)

    return auth


def save_auth(options, auth):
    session = options.session_file or DEFAULT_SESSION_FILE
    path, _ = split(session)

    if not exists(path):
        makedirs(path, 0700)

    auth.save(session)
    chmod(session, 0600)


def cli_command_auth_connect(options):
    auth = options.auth

    if options.refresh and auth.accessToken:
        # user requested we try to reuse the existing session if
        # possible.
        if auth.validate():
            # hey it still works, great, we're done here.
            return 0
        else:
            # well it isn't still valid, let's see if we can refresh
            # it instead.
            try:
                auth.refresh()
            except:
                # nope, refresh failed, fall through to normal full
                # authentication call
                pass
            else:
                # refresh worked, we're done here.
                save_auth(options, auth)
                return 0

    password = options.password or \
               getpass("password for %s: " % auth.username)

    if options.request_client_token:
        # we have explicitly been told to have the server give us
        # a token, even if we had one saved.
        auth.clientToken = None

    elif not auth.clientToken:
        # otherwise, if we don't have a token already we'd better
        # generate one.
        auth.ensureClientToken()

    auth.authenticate(password)

    save_auth(options, auth)
    return 0


def cli_subparser_auth_connect(parent):
    p = subparser(parent, "connect", cli_command_auth_connect)

    p.add_argument("--refresh", action="store_true", default=False,
                   help="refresh rather than re-auth if possible")

    p.add_argument("--user", action="store",
                   help="Mojang username")

    p.add_argument("--password", action="store",
                   help="Mojang password")

    p.add_argument("--request-client-token", action="store_true",
                   help="Request that the server provide a client token")


def cli_command_auth_validate(options):
    auth = options.auth

    if auth.validate():
        print "Session is valid"
        return 0
    else:
        print "Session is no longer valid"
        return -1


def cli_subparser_auth_validate(parent):
    p = subparser(parent, "validate", cli_command_auth_validate)


def cli_command_auth_refresh(options):
    auth = options.auth

    if not auth.accessToken:
        print "No session data"
        return -1

    if options.force:
        auth.refresh()
        return 0

    else:
        try:
            auth.validate()
        except:
            auth.refresh()
        return 0


def cli_subparser_auth_refresh(parent):
    p = subparser(parent, "refresh", cli_command_auth_refresh)

    p.add_argument("--force", action="store_true",
                   help="refresh even if session is valid")


def cli_command_auth_invalidate(options):
    auth = options.auth

    if not auth.accessToken:
        print "No session data"
        return -1
    else:
        auth.invalidate()
        auth.accessToken = None
        save_auth(options, auth)
        return 0


def cli_subparser_auth_invalidate(parent):
    p = subparser(parent, "invalidate", cli_command_auth_invalidate)


def cli_command_auth_signout(options):
    auth = Authentication(options.user, host=options.auth_host)

    password = options.password or \
               getpass("password for %s: " % auth.username)

    auth.signout(password)
    return 0


def cli_subparser_auth_signout(parent):
    p = subparser(parent, "signout", cli_command_auth_signout)

    p.add_argument("--user", action="store",
                   help="Mojang username")

    p.add_argument("--password", action="store",
                   help="Mojang password")


def cli_subparser_auth(parent):
    p = subparser(parent, "auth")

    p.add_argument("--auth-host", action="store",
                   help="Mojang authentication host")

    cli_subparser_auth_connect(p)
    cli_subparser_auth_validate(p)
    cli_subparser_auth_refresh(p)
    cli_subparser_auth_invalidate(p)
    cli_subparser_auth_signout(p)


# --- gnajom realms commands ---


def load_api(options):
    auth = options.auth
    auth.validate()
    return RealmsAPI(auth, options.realms_host, options.realms_version)


def cli_command_realm_list(options):
    api = load_api(options)
    print api.realm_list()
    return 0


def cli_subparser_realm_list(parent):
    p = subparser(parent, "list", cli_command_realm_list)


def cli_command_realm_info(options):
    api = load_api(options)

    info = api.realm_info(options.realm_id)

    print "Realm %i: %s" % (info["id"], info["name"])

    print "  Owner:", info["owner"]

    if info["motd"]:
        print "  Message:", info["motd"]

    print "  Options:"
    print "    maxPlayers:", info["maxPlayers"]
    print "    worldType:", info["worldType"]

    #io = info["options"]
    #print "    PvP: %{pvp}r" % io
    #print "    spawnProtection: %{spawnProtection}i" % io
    #print "    commandBlocks: %{commandBlocks}" % io

    player_count = 0
    player_online = 0
    for player in info["players"]:
        player_count += 1
        if player["online"]:
            player_online += 1

    print "  Players: %i/%i Online" % (player_online, player_count)
    for player in info["players"]:
        print "    ", player["name"],
        if player["operator"]:
            print "[op]",
        if player["online"]:
            print "[online]",
        if not player["accepted"]:
            print "[pending]",
        print


def cli_subparser_realm_info(parent):
    p = subparser(parent, "info", cli_command_realm_info)

    p.add_argument("realm_id", action="store", type=int)


def cli_command_realm_backups(options):
    api = load_api(options)
    print api.realm_backups(options.realm_id)
    return 0


def cli_subparser_realm_backups(parent):
    p = subparser(parent, "backups", cli_command_realm_backups)

    p.add_argument("realm_id", action="store", type=int)


def cli_command_realm_download(options):
    api = load_api(options)

    url = api.realm_world_url(options.realm_id, options.world_number)
    dl = url.get("downloadLink")

    if not url:
        print "Could not get download link for specified realm/world"
        return -1

    if options.just_url:
        print dl
        return 0

    filename = options.filename
    total_size = 0
    try:
        resp = requests.get(dl, stream=True)
        with open(filename, "wb") as out:
            for chunk in resp.iter_content(chunk_size=2**20):
                out.write(chunk)
                total_size += len(chunk)
    except Exception as e:
        print e
        return -1

    else:
        print "Saved world to %s (size: %i)" % (filename, total_size)
        return 0


def cli_subparser_realm_download(parent):
    p = subparser(parent, "download", cli_command_realm_download)

    p.add_argument("realm_id", action="store", type=int)
    p.add_argument("world_number", action="store", type=int)
    p.add_argument("--just-url", action="store_true")
    p.add_argument("--filename", action="store", default="mc_world.tar.gz")


def cli_subparser_realms(parent):
    p = subparser(parent, "realm")

    p.add_argument("--realms-host", action="store",
                   help="Mojang Realms API host to use")

    cli_subparser_realm_list(p)
    cli_subparser_realm_info(p)
    cli_subparser_realm_backups(p)
    cli_subparser_realm_download(p)


# --- CLI setup and entry point ---


def subparser(parser, name, cli_func=None, help=None):
    # the default behaviour for subcommands is kinda shit. They don't
    # properly inherit defaults, and for some idiotic reason running
    # add_subparsers doesn't give you the same subparser to add more
    # subcommands to, it just errors.

    if parser._subparsers:
        subs = parser._subparsers._actions[-1]
    else:
        subs = parser.add_subparsers()
    sp = subs.add_parser(name, help=help)

    sp._defaults.update(parser._defaults)

    if cli_func:
        sp.set_defaults(cli_func=cli_func)

    return sp


def cli_argparser(argv):
    # eat the --config option if one exists and use it to pre-populate
    # option values for a real option parse afterwards.
    parser = ArgumentParser(add_help=False)
    parser.set_defaults(config=DEFAULT_CONFIG_FILE)
    parser.add_argument("-c", "--config-file", action="store")
    options, _ = parser.parse_known_args(argv[1:])

    # and here's our real parser.
    parser = ArgumentParser(prog=basename(argv[0]),
                            conflict_handler="resolve",
                            description="Command line tools for dealing with"
                            " Mojang's Yggdrasil and Realm APIs")

    # set the in-built defaults
    parser.set_defaults(**DEFAULTS)

    # update the defaults from the config file
    config = SafeConfigParser()
    if config.read([options.config]):
        parser.set_defaults(**dict(config.items("defaults")))

    parser.add_argument("-c", "--config-file", action="store",
                        help="Configuration file")
    parser.add_argument("-s", "--session-file", action="store",
                        help="Session auth file")

    cli_subparser_auth(parser)
    cli_subparser_realms(parser)

    return parser


def main(argv=None):
    """
    Primary CLI entry-point.
    """

    argv = argv or sys.argv

    # argparse does silly things. It treats argv[0] special ONLY when
    # argv is not passed to parse_args explicitly. If passed
    # explicitly, then it will act as if argv[0] is the first option
    # rather than the command name.

    try:
        options = cli_argparser(argv).parse_args(argv[1:])
        options.auth = load_auth(options)

        # cli_func is defined as a default value for each individual
        # subcommand parser.
        return options.cli_func(options) or 0

    except KeyboardInterrupt:
        print >> sys.stderr
        return 130


if __name__ == "__main__":
    sys.exit(main())


#
# The end.
