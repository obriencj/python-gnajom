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


from __future__ import print_function

import re
import requests
import sys

from appdirs import AppDirs
from argparse import (
    ArgumentError, ArgumentParser, FileType,
    _AppendAction, _AppendConstAction, _StoreAction, _StoreConstAction, )
from datetime import datetime
from getpass import getpass
from json import dump, load, loads
from os import chmod, makedirs
from os.path import basename, exists, join, split
from requests.exceptions import HTTPError
from time import sleep
from configparser import SafeConfigParser

from . import APICache

from .auth import Authentication, DEFAULT_AUTH_HOST, GNAJOM_CLIENT_TOKEN

from .realms import RealmsAPI, DEFAULT_REALMS_HOST, DEFAULT_REALMS_VERSION

from .mojang import (
    MojangAPI, SessionAPI, StatusAPI,
    DEFAULT_MOJANG_API_HOST, DEFAULT_MOJANG_SESSION_HOST,
    DEFAULT_MOJANG_STATUS_HOST,
    STATISTIC_MINECRAFT_SOLD, STATISTIC_PREPAID_MINECRAFT_REDEEMED,
    STATISTIC_COBALT_SOLD, STATISTIC_SCROLLS_SOLD, )

from .slp import legacy_slp


_APPDIR = AppDirs("gnajom")

DEFAULT_CONFIG_FILE = join(_APPDIR.user_config_dir, "config")
DEFAULT_SESSION_FILE = join(_APPDIR.user_config_dir, "session")

DEFAULT_CACHE_FILE = join(_APPDIR.user_cache_dir, "api_cache")
DEFAULT_CACHE_TYPE = "sqlite"
DEFAULT_CACHE_EXPIRY = 600  # in seconds


# this represents the initial settings of these values on the options
# namespace object we'll eventually pass around to all the cli
# functions. These values may be overridden in the config file, or by
# specifying `-O KEY=VAL`
DEFAULTS = {
    "config_file": DEFAULT_CONFIG_FILE,
    "session_file": DEFAULT_SESSION_FILE,
    "auth_host": DEFAULT_AUTH_HOST,
    "realms_host": DEFAULT_REALMS_HOST,
    "realms_version": DEFAULT_REALMS_VERSION,
    "api_host": DEFAULT_MOJANG_API_HOST,
    "session_host": DEFAULT_MOJANG_SESSION_HOST,
    "status_host": DEFAULT_MOJANG_STATUS_HOST,
    "cache_file": DEFAULT_CACHE_FILE,
    "cache_type": DEFAULT_CACHE_TYPE,
    "cache_expiry": DEFAULT_CACHE_EXPIRY,
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
    username = getattr(options, "username", None)
    auth = Authentication(username, host=options.auth_host)

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
            # then this token is trash, throw it out
            auth.accessToken = None

    username = (options.username or auth.username or
                input("username: "))
    password = (options.password or
                getpass("password for %s: " % username))

    if options.request_client_token:
        # we have explicitly been told to have the server give us
        # a token, even if we had one saved.
        auth.clientToken = None

    elif options.random_client_token:
        # we have explicitly been told to generate a new random client
        # token
        auth.clientToken = None
        auth.ensureClientToken()

    else:
        auth.clientToken = options.client_token or GNAJOM_CLIENT_TOKEN

    auth.username = username
    if auth.authenticate(password):
        save_auth(options, auth)
        return 0

    else:
        print("Error: Bad username or password", file=sys.stderr)
        return 1


def cli_subparser_auth_connect(parent):
    p = subparser(parent, "connect", cli_command_auth_connect,
                  help="Connect and create a new auth session")

    p.add_argument("--refresh", action="store_true", default=False,
                   help="refresh rather than re-auth if possible")

    p.add_argument("--username", "-U", action="store",
                   help="Mojang account username")

    p.add_argument("--password", "-P", action="store",
                   help="Mojang account password")

    g = p.add_mutually_exclusive_group()

    g.add_argument("--request-client-token", action="store_true",
                   help="Request that the server provide a client token")

    g.add_argument("--random-client-token", action="store_true",
                   help="Generate a random client token")

    g.add_argument("--client-token", action="store", default=None,
                   help="Use the specified client token")

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
    p = subparser(parent, "validate", cli_command_auth_validate,
                  help="Check that the current auth session is valid")
    return p


def cli_command_auth_refresh(options):
    """
    cli: gnajom auth refresh
    """

    auth = options.auth

    if not auth.accessToken:
        print("No session data to refresh.",
              "Try `gnajom auth connect` instead.",
              file=sys.stderr)
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
    p = subparser(parent, "refresh", cli_command_auth_refresh,
                  help="Refreshes current auth session")

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
    p = subparser(parent, "invalidate", cli_command_auth_invalidate,
                  help="Invalidate the current auth session")
    return p


def cli_command_auth_signout(options):
    """
    cli: gnajom auth signout
    """

    auth = load_auth(options)

    password = (options.password or
                getpass("password for %s: " % auth.username))

    auth.signout(password)
    return 0


def cli_subparser_auth_signout(parent):
    p = subparser(parent, "signout", cli_command_auth_signout,
                  help="Sign out all sessions for this account")

    p.add_argument("--username", "-U", action="store",
                   help="Mojang account username")

    p.add_argument("--password", "-P", action="store",
                   help="Mojang account password")

    return p


_SENSITIVE_MARKERS = ("access", "token", "key", "pass")


def _hide_sensitive(prop, markers=_SENSITIVE_MARKERS, replace="HIDDEN"):
    name = prop["name"]
    check = name.lower()
    for mark in markers:
        if mark in check:
            return {"name": name, "value": replace}
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

            props = show["user"].get("properties", None)
            if props is not None:
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

        props = auth.user.get("properties", None)
        if props:
            print("  properties:")

            if not options.unsafe:
                props = (_hide_sensitive(prop) for prop in props)

            for p in props:
                print("    %s: %s" % (p["name"], p["value"]))

    return 0


def cli_subparser_auth_show(parent):
    p = subparser(parent, "show", cli_command_auth_show,
                  help="Print authentication information")

    optional_json(p)

    p.add_argument("--unsafe", action="store_true",
                   help="Output values which are not safe to share")

    return p


def cli_command_auth_import(options):
    """
    cli: gnajom auth import
    """

    # 1. find the minecraft launcher config
    # 2. load the json, find the sessions portion
    # 3. copy selected session into the specified session file

    lpf = options.launcher_profiles
    if lpf is None:
        mad = AppDirs("minecraft")
        lpfn = join(mad.user_config_dir, "launcher_profiles.json")

        if not exists(lpfn):
            print("No such file:", lpfn, file=sys.stderr)
            return -1

        lpf = open(lpfn, "rt")

    with lpf:
        profiles = load(lpf)

    # this is a convoluted disaster to translate between the two
    # formats, but it works!
    clientToken = profiles["clientToken"]
    selected_user = profiles["selectedUser"]["account"]
    selected_profile = profiles["selectedUser"]["profile"]
    adb = profiles["authenticationDatabase"][selected_user]
    username = adb["username"]
    accessToken = adb["accessToken"]
    adbp = adb["profiles"][selected_profile]
    profilename = adbp["displayName"]

    auth = options.auth
    auth.username = username
    auth.accessToken = accessToken
    auth.clientToken = clientToken
    auth.user["id"] = selected_user
    auth.selectedProfile["id"] = selected_profile
    auth.selectedProfile["name"] = profilename

    # mixing string filenames with the argparse FileType arguments
    # is a real pain in the ass.
    nsf = options.new_session_file
    if nsf is None:
        save_auth(auth, options)
    else:
        with nsf:
            auth.write(nsf)


def cli_subparser_auth_import(parent):
    p = subparser(parent, "import", cli_command_auth_import,
                  help="Import session from Minecraft launcher")

    p.add_argument("new_session_file", nargs="?", default=None,
                   action="store", type=FileType("w"),
                   help="Optional alternative file to write session to, or"
                   " - to write to stdout")

    p.add_argument("--launcher-profiles", default=None,
                   action="store", type=FileType("rt"),
                   help="Path to launcher_profiles.json to load")

    return p


def cli_subparser_auth(parent):
    p = subparser(parent, "auth",
                  help="Commands related to authentication")

    cli_subparser_auth_connect(p)
    cli_subparser_auth_validate(p)
    cli_subparser_auth_refresh(p)
    cli_subparser_auth_invalidate(p)
    cli_subparser_auth_signout(p)
    cli_subparser_auth_show(p)
    cli_subparser_auth_import(p)

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

    hook = _cli_api_debug_hook if options.debug_cache else None

    auth = options.auth
    if auth.validate():
        return RealmsAPI(auth, options.realms_host, options.realms_version,
                         apicache=api_cache(options), debug_hook=hook)
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
    p = subparser(parent, "list", cli_command_realm_list,
                  help="Print realms available to current user")

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
        print("    %s: %s" % (k, info.get(k, "")))

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
    p = subparser(parent, "info", cli_command_realm_info,
                  help="Print detailed information about a realm")

    optional_json(p)

    p.add_argument("realm_id", action="store", type=int)

    return p


def _do_realm_knock(api, realm_id, no_wait=False):
    while(True):
        try:
            return api.realm_join(realm_id)

        except HTTPError as hte:
            if hte.response.status_code == 503:
                # this means the server was asleep, and is most likely
                # coming online from our knock

                if no_wait:
                    # We don't have any data yet, but the user doesn't
                    # want to wait for it to wake, so make up
                    # something and stop retrying.
                    return {'address': None, 'pendingUpdate': False,
                            'knocked': True, }
                else:
                    # we'll give the realms service a moment to create
                    # and start up a server for our realm, then try
                    # again for a response
                    sleep(2)
            else:
                # some other response code, let's propagate that up
                raise


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
    p = subparser(parent, "knock", cli_command_realm_knock,
                  help="Ensure a realm is running, print its IP Address")

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
    p = subparser(parent, "legacyping", cli_command_realm_legacyping,
                  help="Get data from a legacy ping on a realm")
    optional_json(p)

    p.add_argument("realm_id", action="store", type=int)

    p.add_argument("--knock", action="store_true", default=False,
                   help="If the realm is not currently online (no IP"
                   " assigned), then knock and wait for it to wake up")

    return p


_REALM_BACKUP_FMT = "[id: {backupId}] {lastModifiedDate}, {size} bytes"


def cli_command_realm_backups(options):
    """
    cli: gnajom realm backups
    """

    api = realms_api(options)
    data = api.realm_backups(options.realm_id)

    if options.json:
        pretty(data)

    else:
        backups = data["backups"]
        for back in sorted(backups, key=lambda b: b["lastModifiedDate"],
                           reverse=True):

            lmd = int(back["lastModifiedDate"]) // 1000
            lmd = datetime.utcfromtimestamp(lmd)
            back["lastModifiedDate"] = lmd

            print(_REALM_BACKUP_FMT.format(**back))
            if options.details:
                details = back["metadata"]
                print("  Name:", details["name"])
                print("  Description:", details["description"])
                print("  Difficulty:", details["game_difficulty"])
                print("  Mode:", details["game_mode"])
                print("  Type:", details["world_type"])

    return 0


def cli_subparser_realm_backups(parent):
    p = subparser(parent, "backups", cli_command_realm_backups,
                  help="List available backups for a realm")

    p.add_argument("realm_id", action="store", type=int,
                   help="ID of realm to which this account has admin access")

    p.add_argument("--details", action="store_true", default=False,
                   help="Show additional details for each backup")

    optional_json(p)

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
    p = subparser(parent, "download", cli_command_realm_download,
                  help="Download world data from a realm")

    p.add_argument("realm_id", action="store", type=int)
    p.add_argument("world_number", action="store", type=int)
    p.add_argument("--just-url", action="store_true", default=False,
                   help="print the URL rather than actually downloading")
    p.add_argument("--filename", action="store", default="mc_world.tar.gz")

    return p


def cli_subparser_realms(parent):
    p = subparser(parent, "realm",
                  help="Commands related to Mojang's Minecraft Realms")

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

    hook = _cli_api_debug_hook if options.debug_cache else None

    auth = options.auth
    if auth.validate():
        return MojangAPI(auth, options.api_host,
                         apicache=api_cache(options), debug_hook=hook)
    else:
        raise SessionInvalid()


def session_api(options):
    """
    Fetch a SessionAPI instance configured with our current session.
    Verify that the current session is available for use -- if not
    trigger an exception that will notify the CLI user that they need
    to log in before proceeding.
    """

    hook = _cli_api_debug_hook if options.debug_cache else None

    auth = options.auth
    if auth.validate():
        return SessionAPI(auth, options.session_host,
                          apicache=api_cache(options), debug_hook=hook)
    else:
        raise SessionInvalid()


_WHOAMI_DATE_FIELDS = ("dateOfBirth", "migratedAt",
                       "passwordChangedAt", "registeredAt", )


def cli_command_player_whoami(options):
    """
    cli: gnajom player whoami
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


def cli_subparser_player_whoami(parent):
    p = subparser(parent, "whoami", cli_command_player_whoami)
    optional_json(p)

    return p


def cli_command_player_history(options):
    """
    cli: gnajom user history
    """

    api = mojang_api(options)
    data = api.uuid_name_history(_pick_profile_uuid(options))

    if options.json:
        pretty(data)

    else:
        timeline = [(moment.get("changedToAt", 0), moment["name"])
                    for moment in data]

        for when, name in sorted(timeline):
            if not when:
                print("created as", name)
            else:
                whenat = datetime.utcfromtimestamp(when // 1000)
                print("changed to %s at %s" % (name, whenat))

    return 0


def cli_subparser_player_history(parent):
    p = subparser(parent, "history", cli_command_player_history)

    optional_json(p)

    p.add_argument("profile_uuid", nargs="?", action="store",
                   help="user to show history for (defaults to auth user)")

    p.add_argument("--by-name", action="store_true", default=False,
                   help="user specified by name instead of UUID")

    return p


def _fmt(fmt):
    return lambda d: datetime.strptime(d, fmt)


_DATE_FORMATS = (
    (re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}"), _fmt("%Y-%m-%dT%H:%M")),
    (re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}"), _fmt("%Y-%m-%d %H:%M")),
    (re.compile(r"\d{4}-\d{2}-\d{2}"), _fmt("%Y-%m-%d")),
    (re.compile(r"\d{4}-\d{2}"), _fmt("%Y-%m")),
    (re.compile(r"\d+"), lambda d: datetime.fromtimestamp(int(d))),
)


def datetime_arg(sdate):
    for rc, fmt in _DATE_FORMATS:
        mtch = rc.match(sdate)
        if mtch:
            try:
                return fmt(mtch.string)
            except ValueError as ve:
                raise ArgumentError(str(ve))
    else:
        raise ArgumentError("Invalid date-time format, %r" % sdate)


# we setting the __name__ because that's how argparse will complain
# about the type if an ArgumentError is raised
datetime_arg.__name__ = "date-time"


def cli_command_player_profile(options):
    """
    cli: gnajom user profile
    """

    api = mojang_api(options)

    whenat = options.date
    timestamp = int(whenat.timestamp()) if whenat else None

    try:
        info = api.username_to_uuid(options.search_username, timestamp)

    except HTTPError as http_err:
        if http_err.response.status_code == 404:
            info = None
        else:
            raise

    if options.json:
        pretty(info)
        return 0

    elif info:
        print(info["name"], info["id"])
        return 0

    else:
        msg = "No match for username: %s" % options.search_username
        print(msg, file=sys.stderr)
        return 1


def cli_subparser_player_profile(parent):
    p = subparser(parent, "profile", cli_command_player_profile)

    optional_json(p)

    p.add_argument("search_username",
                   help="username to search for")

    p.add_argument("--date", default=None, type=datetime_arg,
                   help="ISO-8601 formatted date to search at")

    return p


def cli_subparser_player(parent):
    p = subparser(parent, "user",
                  help="Commands related to user accounts")

    cli_subparser_player_whoami(p)
    cli_subparser_player_history(p)
    cli_subparser_player_profile(p)

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

    optional_json(p)

    p.add_argument("search_players", nargs="*", action="store", type=str,
                   help="usernames to look up")

    p.add_argument("--from-file", action="store", type=FileType('r'),
                   help="load list of usernames from file, or - for stdin")

    return p


def _pick_profile_uuid(options):
    """
    Returns a UUID string based on the presence of a profile_uuid
    option, and the --by-name flag. If profile_uuid is not specified,
    then it defaults to the auth data.
    """

    search_val = getattr(options, "profile_uuid", None)
    if not search_val:
        if options.by_name:
            search_val = options.auth.selectedProfile["name"]
        else:
            search_val = options.auth.selectedProfile["id"]
        options.profile_uuid = search_val

    if options.by_name:
        api = mojang_api(options)
        found = api.username_to_uuid(search_val, None)
        uuid = found.get("id", None) if found else None

    else:
        uuid = search_val

    return uuid


def _fetch_profile(options):
    """
    This is used by a few commands to fetch profile data either by
    profile UUID or by profile name.

    It presumes that the options will have profile_uuid and by_name
    """

    api = session_api(options)
    return api.profile_info(_pick_profile_uuid(options))


def cli_command_profile_info(options):
    """
    cli: gnajom profile info
    """

    info = _fetch_profile(options)

    if options.json:
        pretty(info)

    else:
        # TODO, this is a crap output
        for k, v in info.items():
            print("%s: %r" % (k, v))

    return 0


def cli_subparser_profile_info(parent):
    p = subparser(parent, "info", cli_command_profile_info,
                  help="Show information about a profile")

    optional_json(p)

    p.add_argument("profile_uuid", action="store")

    p.add_argument("--by-name", action="store_true",
                   help="specify profile by name instead of by UUID")

    return p


def cli_subparser_profile(parent):
    p = subparser(parent, "profile",
                  help="Commands related to player profiles")

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
    p = subparser(parent, "status", cli_command_status,
                  help="Show the status of public Mojang services")

    optional_json(p)

    return p


def cli_command_statistics(options):
    """
    cli: gnajom statistics
    """

    api = mojang_api(options)

    if options.stats:
        stat = api.statistics(options.stats)
    else:
        stat = api.statistics()

    if options.json:
        pretty(stat)

    else:
        print("Statistic Totals:")
        for k, v in sorted(stat.items()):
            print("  %s: %s" % (k, v))

    return 0


def cli_subparser_statistics(parent):
    p = subparser(parent, "statistics", cli_command_statistics,
                  help="Show Mojang's sales statistics")

    optional_json(p)

    p.add_argument("--minecraft", action="append_const", dest="stats",
                   const=STATISTIC_MINECRAFT_SOLD,
                   help="Minecraft copies sold")

    p.add_argument("--minecraft-prepaid", action="append_const", dest="stats",
                   const=STATISTIC_PREPAID_MINECRAFT_REDEEMED,
                   help="Minecraft prepaid cards redeemed")

    p.add_argument("--cobalt", action="append_const", dest="stats",
                   const=STATISTIC_COBALT_SOLD,
                   help="Cobalt copies sold")

    p.add_argument("--scrolls", action="append_const", dest="stats",
                   const=STATISTIC_SCROLLS_SOLD,
                   help="Scrolls copies sold")

    p.add_argument("--other", action="append", dest="stats",
                   help="Specify an arbitrary statistic key")

    return p


def cli_command_skin_change(options):
    """
    cli: gnajom skin change
    """

    print("NYI")
    return 0


def cli_subparser_skin_change(parent):
    p = subparser(parent, "change", cli_command_skin_change,
                  help="Set profile skin to an existing skin URL")

    return p


def cli_command_skin_upload(options):
    """
    cli: gnajom skin upload
    """

    uuid = _pick_profile_uuid(options)

    api = mojang_api(options)
    api.upload_skin(uuid, options.skin_file, options.slim_model)

    return 0


def cli_subparser_skin_upload(parent):
    p = subparser(parent, "upload", cli_command_skin_upload,
                  help="Upload a file and set it as the profile skin")

    p.add_argument("skin_file", action="store", type=FileType('rb'),
                   help="Skin image file")

    p.add_argument("profile_uuid", nargs="?", action="store",
                   help="profile to reset skin (defaults to auth profile)")

    p.add_argument("--by-name", action="store_true", default=False,
                   help="profile specified by name instead of UUID")

    p.add_argument("--slim-model", action="store_true",
                   help="Use the slim (Alex) model with this skin")

    return p


def cli_command_skin_reset(options):
    """
    cli: gnajom skin reset
    """

    uuid = _pick_profile_uuid(options)

    api = mojang_api(options)
    api.reset_skin(uuid)

    return 0


def cli_subparser_skin_reset(parent):
    p = subparser(parent, "reset", cli_command_skin_reset,
                  help="Reset a profile's skin to the default")

    p.add_argument("profile_uuid", nargs="?", action="store",
                   help="profile to set skin (defaults to auth profile)")

    p.add_argument("--by-name", action="store_true", default=False,
                   help="profile specified by name instead of UUID")

    return p


def cli_command_skin_download(options):
    """
    cli: gnajom skin download
    """

    info = _fetch_profile(options)
    if not info:
        print("Profile not found: %s" % options.profile_uuid, file=sys.stderr)
        return 1

    texture = None
    for prop in info.get("properties", ()):
        if prop["name"] == "textures":
            texture = prop["value"]
            break
    else:
        print("Profile has no texture data", file=sys.stderr)
        return 1

    skin_data = texture["textures"].get("SKIN")
    skin_url = skin_data.get("url") if skin_data else None

    if not skin_url:
        print("Profile has no skin data", file=sys.stderr)
        return 1

    if options.just_url:
        print(skin_url)
        return 0

    filename = options.filename or ("%s.png" % info["name"])
    total_size = 0
    try:
        resp = requests.get(skin_url, stream=True)
        with open(filename, "wb") as out:
            for chunk in resp.iter_content(chunk_size=2**20):
                out.write(chunk)
                total_size += len(chunk)

    except Exception as e:
        print(e)
        return -1

    else:
        print("Saved skin to %s (size: %i)" % (filename, total_size))
        return 0


def cli_subparser_skin_download(parent):
    p = subparser(parent, "download", cli_command_skin_download,
                  help="Download the skin for a profile")

    p.add_argument("profile_uuid", nargs="?", action="store",
                   help="profile to fetch skin from (defaults to auth"
                   " profile)")

    p.add_argument("--by-name", action="store_true", default=False,
                   help="profile specified by name instead of UUID")

    p.add_argument("--just-url", action="store_true", default=False,
                   help="print the URL rather than actually downloading")

    p.add_argument("--filename", action="store", default=None,
                   help="filename to save to, defaults to profile name")

    return p


def cli_subparser_skin(parent):
    p = subparser(parent, "skin",
                  help="Commands related to Minecraft skin services")

    cli_subparser_skin_change(p)
    cli_subparser_skin_upload(p)
    cli_subparser_skin_reset(p)
    cli_subparser_skin_download(p)

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
#    return p


def cli_command_config_write(options):
    """
    cli: gnajom config write
    """

    cparser = SafeConfigParser()
    cparser.add_section("defaults")

    for key, val in sorted(DEFAULTS.items()):
        if key == "config_file":
            continue

        val = getattr(options, key, val)
        cparser.set("defaults", key, str(val))

    output = options.new_conf_file
    if not output:
        config_file = options.config_file
        config_dir, _ = split(config_file)
        if not exists(config_dir):
            makedirs(config_dir)
        output = open(config_file, "wt")

    with output:
        cparser.write(output)


def cli_subparser_config_write(parent):
    p = subparser(parent, "write", cli_command_config_write,
                  help="Write out a conf file from current configuration")

    p.add_argument("new_conf_file", nargs="?", default=None,
                   action="store", type=FileType('w'),
                   help="Optional alternative file to write config, or"
                   " - to write to stdout")

    return p


def cli_command_config_show(options):
    """
    cli: gnajom config show
    """

    # this should represent the DEFAULTS, and any configuration values
    # loaded from the config file on top of that.
    for key, val in sorted(DEFAULTS.items()):
        val = getattr(options, key, val)
        print("%s: %r" % (key, val))

    return 0


def cli_subparser_config_show(parent):
    p = subparser(parent, "show", cli_command_config_show,
                  help="Print current configuration setting")

    return p


def cli_subparser_config(parent):
    p = subparser(parent, "config",
                  help="Commands for dealing with CLI configuration")

    cli_subparser_config_write(p)
    cli_subparser_config_show(p)

    return p


# --- CLI setup and entry point ---


def _cli_api_debug_hook(response):
    from_cache = getattr(response, "from_cache", None)
    msg = "cached: %r, response: %r" % (from_cache, response)
    print(msg, file=sys.stderr)
    return response


def safe_int(val, default=0):
    try:
        val = int(val)
    except ValueError:
        val = default
    return val


def api_cache(options):
    cache = getattr(options, "cache", None)

    if cache is None:
        expiry = safe_int(options.cache_expiry, DEFAULT_CACHE_EXPIRY)
        cache_file = options.cache_file or DEFAULT_CACHE_FILE
        cache_type = options.cache_type or DEFAULT_CACHE_TYPE

        path, _ = split(cache_file)
        if not exists(path):
            makedirs(path)

        cache = APICache(cache_file, cache_type, expiry)
        options.cache = cache

    return cache


def optional_json(parser):
    parser.add_argument("--json", action="store_true",
                        help="Output results as formatted JSON")
    return parser


# these are the action types which we want to inherit in subparsers
_inherit_actions = (
    _AppendAction, _AppendConstAction,
    _StoreAction, _StoreConstAction, )


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
    sp = subs.add_parser(name, help=help, description=help)

    # "inherit" the parent command optional arguments
    for act in parser._subparsers._actions:
        if isinstance(act, _inherit_actions):
            sp._add_action(act)

    # "inherit" the parent command defaults
    sp._defaults.update(parser._defaults)

    # cli_func will be what is called when this subparser is the last
    # command given. In instances where the subparser is only used to
    # gather up a group of sub-commands, then we'll use this function
    # to print help information.
    if cli_func is None:
        def cli_func(_):
            sp.print_usage(sys.stderr)
            return 1

    # set the cli handler function for this command. We just borrow a
    # defaults value for this purpose.
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

    # the cli_func default is used when no subparser is triggered. In
    # this case, we just want it to print out the usage message
    def cli_func(_):
        parser.print_usage(sys.stderr)
        return 1

    parser.set_defaults(cli_func=cli_func)

    # this argument doesn't do anything, we just want it visible for
    # invocations of --help, any actual loading of the config put data
    # into the defaults
    parser.add_argument("-c", "--config-file", action="store",
                        help="Configuration file")

    parser.add_argument("-s", "--session-file", action="store",
                        help="Session auth file")

    parser.add_argument("-O", dest="opt_val", action="append", default=list(),
                        help="Configuration to override, as var=val")

    parser.add_argument("--debug-cache", action="store_true", default=False,
                        help="Print debugging information about cached calls")

    cli_subparser_auth(parser)
    cli_subparser_realms(parser)
    cli_subparser_status(parser)
    cli_subparser_statistics(parser)
    cli_subparser_player(parser)
    cli_subparser_profile(parser)
    cli_subparser_skin(parser)
    # cli_subparser_blocked(parser)
    cli_subparser_config(parser)

    return parser


def handle_magic_opts(options):
    """
    Used by `main()` to organize and transform some option settings
    """

    # go through the -O opts, split them as key=val and any key in
    # DEFAULTS can be used to override the value currently in options
    for opt in options.opt_val:
        key, val = opt.split("=", 1)
        if key in DEFAULTS:
            setattr(options, key, val)

    # we'll always want an auth object, so get one
    options.auth = load_auth(options)

    return options


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
        options = handle_magic_opts(options)

        # there should never be a point where cli_func isn't set.
        assert(options.cli_func is not None)

        # cli_func is defined as a default value for each individual
        # subcommand parser, see subparser()
        return options.cli_func(options) or 0

    except SessionInvalid:
        print("Current session invalid. Try running"
              " `gnajom auth connect --refresh`", file=sys.stderr)
        return 1

    except HTTPError as http_err:
        resp = http_err.response
        if resp.status_code in (403, 429):
            # these are a somewhat expected occurance, so we want to
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
