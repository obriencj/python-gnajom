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
Provides access to various aspects of the APIs via a nested command
system.

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


# Note that this is by far the largest module in this package,
# primarily because it has to act as the front-end between human-input
# and human-readable output.


import requests
import sys

from argparse import ArgumentParser, FileType, _StoreAction, _StoreConstAction
from datetime import datetime
from getpass import getpass

from json import dump, loads
from os import chmod, makedirs
from os.path import basename, exists, expanduser, split
from requests.exceptions import HTTPError
from time import sleep
from configparser import SafeConfigParser

from .auth import Authentication, DEFAULT_AUTH_HOST

from .realms import RealmsAPI, DEFAULT_REALMS_HOST, DEFAULT_REALMS_VERSION

from .mojang import (MojangAPI, SessionAPI, StatusAPI,
                     DEFAULT_MOJANG_API_HOST, DEFAULT_MOJANG_SESSION_HOST,
                     DEFAULT_MOJANG_STATUS_HOST)

from .slp import legacy_slp


DEFAULT_CONFIG_FILE = expanduser("~/.gnajom/gnajom.conf")
DEFAULT_SESSION_FILE = expanduser("~/.gnajom/session")


DEFAULTS = {
    "username": None,
    "config_file": DEFAULT_CONFIG_FILE,
    "session_file": DEFAULT_SESSION_FILE,
    "auth_host": DEFAULT_AUTH_HOST,
    "realms_host": DEFAULT_REALMS_HOST,
    "realms_version": DEFAULT_REALMS_VERSION,
    "api_host": DEFAULT_MOJANG_API_HOST,
    "session_host": DEFAULT_MOJANG_SESSION_HOST,
    "status_host": DEFAULT_MOJANG_STATUS_HOST,
}


class SessionInvalid(Exception):
    """
    raised by various api utility functions if they require a valid
    auth and don't get one. caught in main to inform user they need to
    connect
    """

    pass


def pretty(obj, out=sys.stdout):
    """
    utility for dumping json pretty-printed, usually when the --json
    option is passed to a command
    """

    dump(obj, out, indent=4, separators=(', ', ': '), sort_keys=True)
    print(file=out)


# --- gnajom auth commands ---


def load_auth(options):
    # print "load_auth", options.username, options.session_file

    auth = Authentication(options.username, host=options.auth_host)

    session = options.session_file or DEFAULT_SESSION_FILE
    if exists(session):
        auth.load(session)

    return auth


def save_auth(options, auth):
    session = options.session_file or DEFAULT_SESSION_FILE
    path, _ = split(session)

    if not exists(path):
        makedirs(path, 0o700)

    auth.save(session)
    chmod(session, 0o600)


def cli_command_auth_connect(options):
    """
    cli: gnajom auth connect
    """

    print("cli_command_auth_connect", options.username, options.session_file)

    auth = options.auth

    if options.refresh and auth.accessToken:
        # user requested we try to reuse the existing session if
        # possible.

        if auth.validate():
            # hey it still works, great, we're done here.
            return 0

        elif auth.refresh():
            # it wasn't valid, but we were able to refresh it, so
            # we're good to go. Make sure we save out updated
            # accessToken to the session file.
            save_auth(options, auth)
            return 0

        else:
            # then this stuff is trash, throw it out
            auth.accessToken = None
            auth.clientToken = None

    password = (options.password or
                getpass("password for %s: " % auth.username))

    if options.request_client_token:
        # we have explicitly been told to have the server give us
        # a token, even if we had one saved.
        auth.clientToken = None

    elif not auth.clientToken:
        # otherwise, if we don't have a token already we'd better
        # generate one.
        auth.ensureClientToken()

    if auth.authenticate(password):
        save_auth(options, auth)
        return 0

    else:
        print("Error: Bad username or password", file=sys.stderr)
        return 1


def cli_subparser_auth_connect(parent):
    p = subparser(parent, "connect", cli_command_auth_connect)
    optional_auth_host(p)

    p.add_argument("--refresh", action="store_true", default=False,
                   help="refresh rather than re-auth if possible")

    p.add_argument("--user", action="store", dest="username",
                   help="Mojang username")

    p.add_argument("--password", action="store",
                   help="Mojang password")

    p.add_argument("--request-client-token", action="store_true",
                   help="Request that the server provide a client token")

    return p


def cli_command_auth_validate(options):
    """
    cli: gnajom auth validate
    """

    auth = options.auth

    if auth.validate():
        print("Session is valid")
        return 0
    else:
        print("Session is no longer valid")
        return -1


def cli_subparser_auth_validate(parent):
    p = subparser(parent, "validate", cli_command_auth_validate)
    return p


def cli_command_auth_refresh(options):
    """
    cli: gnajom auth refresh
    """

    auth = options.auth

    if not auth.accessToken:
        print("No session data")
        return -1

    if options.force or not auth.validate():
        if auth.refresh():
            save_auth(options, auth)
            return 0
        else:
            print("Could not refresh session.", file=sys.stderr)
            return 1
    else:
        # we weren't told to force refresh, and the session is still
        # valid, so we're happy with the way things are.
        return 0


def cli_subparser_auth_refresh(parent):
    p = subparser(parent, "refresh", cli_command_auth_refresh)

    p.add_argument("--force", action="store_true",
                   help="refresh even if session is valid")

    return p


def cli_command_auth_invalidate(options):
    """
    cli: gnajom auth invalidate
    """

    auth = options.auth

    if not auth.accessToken:
        print("No session data")
        return -1
    else:
        auth.invalidate()
        save_auth(options, auth)
        return 0


def cli_subparser_auth_invalidate(parent):
    p = subparser(parent, "invalidate", cli_command_auth_invalidate)
    return p


def cli_command_auth_signout(options):
    """
    cli: gnajom auth signout
    """

    # use a clean Authentication rather than a loaded session
    auth = Authentication(options.username, host=options.auth_host)

    password = (options.password or
                getpass("password for %s: " % auth.username))

    auth.signout(password)
    return 0


def cli_subparser_auth_signout(parent):
    p = subparser(parent, "signout", cli_command_auth_signout)
    optional_auth_host(p)

    p.add_argument("--user", action="store", dest="username",
                   help="Mojang username")

    p.add_argument("--password", action="store",
                   help="Mojang password")

    return p


_SENSITIVE_MARKERS = ("access", "token", "key", "pass")


def _hide_sensitive(prop, markers=_SENSITIVE_MARKERS):
    name = prop["name"].lower()
    check = name.lower()
    for mark in markers:
        if mark in check:
            return {"name": name, "value": "HIDDEN"}
    else:
        return prop


def cli_command_auth_show(options):
    """
    cli: gnajom auth show
    """

    auth = options.auth

    if options.json:
        show = dict(auth.__dict__)
        show["host"] = auth.api._host
        del show["api"]

        if not options.unsafe:
            show["accessToken"] = "HIDDEN"

            props = show["user"]["properties"]
            props = [_hide_sensitive(prop) for prop in props]
            show["user"]["properties"] = props

        pretty(show)

    else:
        def hide(x):
            return x if options.unsafe else "HIDDEN"

        print("Session file: %s" % options.session_file)
        print("  auth_host:", auth.api._host)
        print("  username:", auth.username)
        print("  id:", auth.user["id"])
        print("  clientToken:", auth.clientToken)
        print("  accessToken:", hide(auth.accessToken))
        print("  selectedProfile:")
        print("    name:", auth.selectedProfile["name"])
        print("    id:", auth.selectedProfile["id"])
        print("  agent:")
        print("    name:", auth.agent["name"])
        print("    version:", auth.agent["version"])

        props = auth.user["properties"]
        if props:
            print("  properties:")

            if not options.unsafe:
                props = (_hide_sensitive(prop) for prop in props)

            for p in props:
                print("    %s: %s" % (p["name"], p["value"]))

    return 0


def cli_subparser_auth_show(parent):
    p = subparser(parent, "show", cli_command_auth_show)
    optional_json(p)

    p.add_argument("--unsafe", action="store_true",
                   help="Output values which are not safe to share")

    return p


def cli_subparser_auth(parent):
    p = subparser(parent, "auth")

    cli_subparser_auth_connect(p)
    cli_subparser_auth_validate(p)
    cli_subparser_auth_refresh(p)
    cli_subparser_auth_invalidate(p)
    cli_subparser_auth_signout(p)
    cli_subparser_auth_show(p)

    return p


# --- gnajom realms commands ---


_REALM_LIST_FMT = "[id: {id}] {name} (owner: {owner})"


def realms_api(options):
    """
    Fetch a RealmsAPI instance configured with our current session.
    Verify that the current session is available for use -- if not
    trigger an exception that will notify the CLI user that they need
    to log in before proceeding.
    """

    auth = options.auth
    if auth.validate():
        return RealmsAPI(auth, options.realms_host, options.realms_version)
    else:
        raise SessionInvalid()


def cli_command_realm_list(options):
    """
    cli: gnajom realm list
    """

    api = realms_api(options)
    data = api.realm_list()

    if options.json:
        pretty(data)
        return 0

    servers = data["servers"]
    for server in sorted(servers, key=lambda d: d["id"]):
        print(_REALM_LIST_FMT.format(**server))
        if options.motd and server.get("motd"):
            print("  MotD: %s" % server["motd"])

        if options.players:
            players = server["players"] or tuple()
            print("  %i players online" % len(players))
            if players:
                print("    \n".join(sorted(players)))

    return 0


def cli_subparser_realm_list(parent):
    p = subparser(parent, "list", cli_command_realm_list)
    optional_json(p)

    p.add_argument("--players", action="store_true", default=False,
                   help="Show online players")

    p.add_argument("--motd", action="store_true", default=False,
                   help="Show message of the day")

    return p


_REALM_INFO_KEYS = ("state", "ip", "maxPlayers", "worldType", "activeSlot",
                    "expired", "daysLeft", "minigameId", "minigameName",
                    "resourcePackUrl", "resourcePackHash", )


def cli_command_realm_info(options):
    """
    cli: gnajom realm info
    """

    api = realms_api(options)
    info = api.realm_info(options.realm_id)

    if options.json:
        pretty(info)
        return 0

    print(_REALM_LIST_FMT.format(**info))
    if info["motd"]:
        print("  MotD:", info["motd"])

    print("  Info:")
    for k in _REALM_INFO_KEYS:
        print("    %s: %s" % (k, info[k]))

    print("  World slots:")
    slots = info["slots"]
    for slot in sorted(slots, key=lambda s: s["slotId"]):
        print("    Slot %i:" % slot["slotId"])
        slot = loads(slot["options"])
        for k, v in sorted(slot.items()):
            print("      %s: %s" % (k, v))

    player_count = 0
    player_online = 0
    for player in info["players"]:
        player_count += 1
        if player["online"]:
            player_online += 1

    print("  Players: %i/%i Online" % (player_online, player_count))
    for player in info["players"]:
        print("    ", player["name"], end=' ')
        if player["operator"]:
            print("[op]", end=' ')
        if player["online"]:
            print("[online]", end=' ')
        if not player["accepted"]:
            print("[pending]", end=' ')
        print()


def cli_subparser_realm_info(parent):
    p = subparser(parent, "info", cli_command_realm_info)
    optional_json(p)

    p.add_argument("realm_id", action="store", type=int)

    return p


def _do_realm_knock(api, realm_id, no_wait=False):
    retry = True
    while(retry):
        try:
            data = api.realm_join(realm_id)

        except HTTPError as hte:
            if hte.response.status_code == 503:
                # this means the server was asleep, and is most likely
                # coming online from our knock

                if no_wait:
                    # We don't have any data yet, but the user doesn't
                    # want to wait for it to wake, so make up
                    # something and stop retrying.
                    retry = False
                    data = {'address': None, 'pending': True}
                else:
                    # we'll give the realms service a moment to create
                    # and start up a server for our realm
                    sleep(2)
            else:
                # some other response code, let's propagate that up
                raise
        else:
            # if there was no error, then we don't need to retry
            retry = False

    return data


def cli_command_realm_knock(options):
    """
    cli: gnajom realm knock
    """

    api = realms_api(options)
    data = _do_realm_knock(api, options.realm_id, options.no_wait)

    if options.json:
        pretty(data)
    elif "pending" in data:
        print("Server is coming online")
    else:
        print("Server is online at", data["address"])

    return 0


def cli_subparser_realm_knock(parent):
    p = subparser(parent, "knock", cli_command_realm_knock)
    optional_json(p)

    p.add_argument("realm_id", action="store", type=int)

    p.add_argument("--no-wait", action="store_true", default=False,
                   help="Do not wait for the realm to come online, return"
                   " immediately even if the address is not yet determined")

    return p


def cli_command_realm_legacyping(options):
    """
    cli: gnajom realm legacyping
    """

    api = realms_api(options)

    if options.knock:
        # just do a knock and get the response from that, since we
        # were probably going to have to do it if the server was
        # asleep anyway
        data = _do_realm_knock(api, options.realm_id)
        data = data["address"]
    else:
        # get the
        data = api.realm_info(options.realm_id)
        data = data["ip"]

    if not data:
        print("Server is offline")
        return -1

    addr, port = data.split(":")
    port = int(port)

    fields = legacy_slp(addr, port)
    print(repr(fields))


def cli_subparser_realm_legacyping(parent):
    p = subparser(parent, "legacyping", cli_command_realm_legacyping)
    optional_json(p)

    p.add_argument("realm_id", action="store", type=int)

    p.add_argument("--knock", action="store_true", default=False,
                   help="If the realm is not currently online (no IP"
                   " assigned), then knock and wait for it to wake up")

    return p


def cli_command_realm_backups(options):
    """
    cli: gnajom realm backups
    """

    api = realms_api(options)
    print(api.realm_backups(options.realm_id))
    return 0


def cli_subparser_realm_backups(parent):
    p = subparser(parent, "backups", cli_command_realm_backups)

    p.add_argument("realm_id", action="store", type=int)

    return p


def cli_command_realm_download(options):
    """
    cli: gnajom realm download
    """

    api = realms_api(options)

    url = api.realm_world_url(options.realm_id, options.world_number)
    dl = url.get("downloadLink")

    if not url:
        print("Could not get download link for specified realm/world")
        return -1

    if options.just_url:
        print(dl)
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
        print(e)
        return -1

    else:
        print("Saved world to %s (size: %i)" % (filename, total_size))
        return 0


def cli_subparser_realm_download(parent):
    p = subparser(parent, "download", cli_command_realm_download)

    p.add_argument("realm_id", action="store", type=int)
    p.add_argument("world_number", action="store", type=int)
    p.add_argument("--just-url", action="store_true")
    p.add_argument("--filename", action="store", default="mc_world.tar.gz")

    return p


def cli_subparser_realms(parent):
    p = subparser(parent, "realm")
    optional_realms_host(p)

    cli_subparser_realm_list(p)
    cli_subparser_realm_info(p)
    cli_subparser_realm_knock(p)
    cli_subparser_realm_legacyping(p)
    cli_subparser_realm_backups(p)
    cli_subparser_realm_download(p)

    return p


# --- mojang core public API ---


def mojang_api(options):
    """
    Fetch a RealmsAPI instance configured with our current session.
    Verify that the current session is available for use -- if not
    trigger an exception that will notify the CLI user that they need
    to log in before proceeding.
    """

    auth = options.auth
    if auth.validate():
        return MojangAPI(auth, options.api_host)
    else:
        raise SessionInvalid()


def session_api(options):
    """
    Fetch a SessionAPI instance configured with our current session.
    Verify that the current session is available for use -- if not
    trigger an exception that will notify the CLI user that they need
    to log in before proceeding.
    """

    auth = options.auth
    if auth.validate():
        return SessionAPI(auth, options.session_host)
    else:
        raise SessionInvalid()


_WHOAMI_DATE_FIELDS = ("dateOfBirth", "migratedAt",
                       "passwordChangedAt", "registeredAt", )


def cli_command_user_whoami(options):
    """
    cli: gnajom user whoami
    """

    api = mojang_api(options)
    info = api.whoami()

    if options.json:
        pretty(info)

    else:
        for key in _WHOAMI_DATE_FIELDS:
            if key in info:
                val = info[key] // 1000
                info[key] = datetime.utcfromtimestamp(val)

        print("Authenticated:")
        for k, v in sorted(info.items()):
            print("  %s: %s" % (k, v))

    return 0


def cli_subparser_user_whoami(parent):
    p = subparser(parent, "whoami", cli_command_user_whoami)
    optional_json(p)

    return p


def cli_command_user_history(options):
    """
    cli: gnajom user history
    """

    print("NYI")
    return 0


def cli_subparser_user_history(parent):
    p = subparser(parent, "history", cli_command_user_history)
    optional_api_host(p)
    optional_json(p)

    return p


def cli_command_user_profile(options):
    """
    cli: gnajom player info
    """

    api = mojang_api(options)
    info = api.username_to_uuid(options.search_username, options.time)

    if options.json:
        pretty(info)
    elif info:
        print("%s %s" % (info["name"], info["id"]))

    return 0


def cli_subparser_user_profile(parent):
    p = subparser(parent, "profile", cli_command_user_profile)
    optional_api_host(p)
    optional_json(p)

    p.add_argument("search_username",
                   help="username to search for")

    p.add_argument("--time", default=0, type=int,
                   help="timestamp to search at")

    return p


def cli_subparser_user(parent):
    p = subparser(parent, "user")

    cli_subparser_user_whoami(p)
    cli_subparser_user_history(p)
    cli_subparser_user_profile(p)

    return p


def cli_command_profile_lookup(options):
    """
    cli: gnajom profile lookup
    """

    search = set(options.search_players)
    if options.from_file:
        search.update(line for line in
                      map(str.strip, options.from_file) if line)

    if not search:
        return 0

    api = mojang_api(options)
    found = api.playernames_to_uuids(search)

    if options.json:
        pretty(found)
    else:
        for f in found:
            print("%s %s" % (f["name"], f["id"]))
    return 0


def cli_subparser_profile_lookup(parent):
    p = subparser(parent, "lookup", cli_command_profile_lookup)
    optional_api_host(p)
    optional_json(p)

    p.add_argument("search_players", nargs="*", action="store", type=str,
                   help="usernames to look up")

    p.add_argument("--from-file", action="store", type=FileType('r'),
                   help="load list of usernames from file, or - for stdin")

    return p


def cli_command_profile_info(options):
    """
    cli: gnajom profile info
    """

    # TODO: we need to cache this and only call to the API if the
    # cached copy is more than 60 seconds old.

    api = session_api(options)
    info = api.profile_info(options.uuid)
    pretty(info)

    return 0


def cli_subparser_profile_info(parent):
    p = subparser(parent, "info", cli_command_profile_info)
    optional_api_host(p)
    optional_json(p)

    p.add_argument("uuid", action="store")

    return p


def cli_subparser_profile(parent):
    p = subparser(parent, "profile")

    cli_subparser_profile_lookup(p)
    cli_subparser_profile_info(p)

    return p


_SERVICE_NAMES = {
    "account.mojang.com": "Mojang accounts website",
    "api.mojang.com": "Mojang Public API",
    "auth.mojang.com": "Mojang authentication (Legacy)",
    "authserver.mojang.com": "Mojang authentication (Yggdrasil)",
    "mcoapi.minecraft.net": "Minecraft Realms",
    "minecraft.net": "Minecraft website",
    "mojang.com": "Mojang website",
    "peoapi.minecraft.net": "Pocked Edition Realms",
    "session.minecraft.net": "Minecraft sessions (Legacy)",
    "sessionserver.mojang.com": "Multiplayer sessions",
    "skins.minecraft.net": "Minecraft skins",
    "status.mojang.com": "Status API",
    "textures.minecraft.net": "Minecraft textures",
}


def cli_command_status(options):
    """
    cli: gnajom status
    """

    api = StatusAPI(None, host=options.status_host)
    stat = api.check()

    if options.json:
        pretty(stat)

    else:
        print("Services:")
        for s in stat:
            for k, v in s.items():
                k = _SERVICE_NAMES.get(k, k)
                print("  %s: %s" % (k, v))

    return 0


def cli_subparser_status(parent):
    p = subparser(parent, "status", cli_command_status)
    optional_status_host(p)
    optional_json(p)

    return p


def cli_command_statistics(options):
    """
    cli: gnajom statistics
    """

    api = mojang_api(options)
    stat = api.statistics()

    if options.json:
        pretty(stat)

    else:
        print("Statistics:")
        for k, v in stat.items():
            print("  %s: %s" % (k, v))

    return 0


def cli_subparser_statistics(parent):
    p = subparser(parent, "statistics", cli_command_statistics)
    optional_api_host(p)
    optional_json(p)

    return p


def cli_command_skin_change(options):
    """
    cli: gnajom skin reset
    """

    print("NYI")
    return 0


def cli_subparser_skin_change(parent):
    p = subparser(parent, "change", cli_command_skin_change)
    optional_api_host(p)

    return p


def cli_command_skin_upload(options):
    """
    cli: gnajom skin reset
    """

    print("NYI")
    return 0


def cli_subparser_skin_upload(parent):
    p = subparser(parent, "upload", cli_command_skin_upload)
    optional_api_host(p)

    return p


def cli_command_skin_reset(options):
    """
    cli: gnajom skin reset
    """

    print("NYI")
    return 0


def cli_subparser_skin_reset(parent):
    p = subparser(parent, "reset", cli_command_skin_reset)
    optional_api_host(p)

    return p


def cli_subparser_skin(parent):
    p = subparser(parent, "skin")

    cli_subparser_skin_change(p)
    cli_subparser_skin_upload(p)
    cli_subparser_skin_reset(p)

    return p


# def cli_command_blocked(options):
#    """
#    cli: gnajom blocked
#    """
#
#    api = session_api(options)
#    info = api.blocked_servers()


# def cli_subparser_blocked(parent):
#    p = subparser(parent, "blocked", cli_command_blocked)
#    optional_session_host(p)


# --- CLI setup and entry point ---


def optional_realms_host(parser):
    parser.add_argument("--realms-host", action="store",
                        help="Mojang Realms API host")
    return parser


def optional_api_host(parser):
    parser.add_argument("--api-host", action="store",
                        help="Mojang Public API host")
    return parser


def optional_session_host(parser):
    parser.add_argument("--session-host", action="store",
                        help="Mojang Sessions API host")
    return parser


def optional_status_host(parser):
    parser.add_argument("--status-host", action="store",
                        help="Mojang Status API host")
    return parser


def optional_auth_host(parser):
    parser.add_argument("--auth-host", action="store",
                        help="Yggdrasil Authentication host")
    return parser


def optional_json(parser):
    parser.add_argument("--json", action="store_true",
                        help="Output results as formatted JSON")
    return parser


def subparser(parser, name, cli_func=None, help=None):
    # the default behaviour for subcommands is kinda shit. They don't
    # properly inherit defaults, nor parent arguments, and for some
    # idiotic reason running add_subparsers doesn't give you the same
    # subparser to add more subcommands to, it just errors. argparse
    # is less of a pancea and more of a pile of crap.

    # pretend add_subparsers is memoized
    if parser._subparsers:
        subs = parser._subparsers._actions[-1]
    else:
        subs = parser.add_subparsers()

    # create the subparser for the command
    sp = subs.add_parser(name, help=help)

    # "inherit" the parent command optional arguments
    for act in parser._subparsers._actions:
        if isinstance(act, (_StoreAction, _StoreConstAction)):
            sp._add_action(act)

    # "inherit" the parent command defaults
    sp._defaults.update(parser._defaults)

    # set the cli handler function for this command
    if cli_func:
        sp.set_defaults(cli_func=cli_func)

    return sp


def cli_argparser(argv=None):

    argv = sys.argv if argv is None else argv

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

    # this argument doesn't do anything, we just want it visible for
    # invocations of --help, any actual loading of the config put data
    # into the defaults
    parser.add_argument("-c", "--config-file", action="store",
                        help="Configuration file")

    parser.add_argument("-s", "--session-file", action="store",
                        help="Session auth file")

    cli_subparser_auth(parser)
    cli_subparser_realms(parser)
    cli_subparser_status(parser)
    cli_subparser_statistics(parser)
    cli_subparser_user(parser)
    cli_subparser_profile(parser)
    cli_subparser_skin(parser)
    # cli_subparser_blocked(parser)

    return parser


def main(argv=None):
    """
    Primary CLI entry-point.
    """

    argv = sys.argv if argv is None else argv

    # argparse does silly things. It treats argv[0] special ONLY when
    # argv is not passed to parse_args explicitly. If passed
    # explicitly, then it will act as if argv[0] is the first option
    # rather than the command name.

    try:
        parser = cli_argparser(argv)
        options = parser.parse_args(argv[1:])
        options.auth = load_auth(options)

        # cli_func is defined as a default value for each individual
        # subcommand parser, see subparser()
        return options.cli_func(options) or 0

    except SessionInvalid:
        print("Current session invalid. Try running"
              " `gnajom auth connect --refresh`", file=sys.stderr)
        return 1

    except HTTPError as http_err:
        if http_err.response.status_code == 429:
            # this is a somewhat expected occurance, so we want to
            # handle it more gracefully than with a backtrace.
            print(http_err, file=sys.stderr)
            return 1

        else:
            # all other HTTP errors get propagated just in case
            raise

    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())


#
# The end.
