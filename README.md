# Overview of python-gnajom

Gnajom is a [Python] module that adds support for accessing [Mojang's]
public APIs.

The primary feature is in controlling a [Minecraft Realms] instance
from the command-line, allowing for automated map generation via
nightly downloads of the latest realm backup.

[Python]: https://www.python.org

[Mojang's]: http://mojang.com

[Minecraft Realms]: http://minecraft.net/realms

The majority of the API information used in this library is straight
from the excellent resource [wiki.vg](http://wiki.vg)


## Command-Line Interface

The `gnajom` command-line interface (or `gnajom.cli.main()`) uses the
argparse package to provide a nested set of commands exposing a
number of available calls in the various Mojang public APIs.

| Command  | Description  |
|----------|--------------|
|`gnajom auth connect` |Connect and create a new auth session |
|`gnajom auth validate` |Check that the current auth session is valid |
|`gnajom auth refresh` |Refreshes current auth session |
|`gnajom auth invalidate` |Invalidates the current auth session |
|`gnajom auth signout`  |Sign out all sessions for this account |
|`gnajom auth show` |Print authentication information |
|`gnajom realm list` |Print realms available to current user |
|`gnajom realm info REALM_ID` |Print detailed information about a realm |
|`gnajom realm knock REALM_ID` |Ensure a realm is running, print its address |
|`gnajom realm backups REALM_ID` |List available backups for a realm |
|`gnajom realm download REALM_ID WORLD_SLOT` |Download world data from a realm |
|`gnajom status` |Show the status of public Mojang services |
|`gnajom statistics` |Show Mojang's sales statistics |
|`gnajom player whoami` |Print information for the current auth account |
|`gnajom player history PLAYER_NAME` |Profile name history for a player |
|`gnajom player profile PLAYER_NAME` |Find a player's profile |
|`gnajom profile lookup PLAYER_NAME ...` |Search for profile information |
|`gnajom profile info PROFILE_ID` |Show information about a profile |
|`gnajom skin change URL` |Set profile skin to an existing skin URL |
|`gnajom skin upload FILE_NAME` |Upload a file and set it as the profile skin |
|`gnajom skin reset` |Reset a profile's skin to the default |
|`gnajom skin download` |Download the skin for a profile |

Some parameter distinctions are necessary:

* a USER is a mojang account, typically named by email address
* a PLAYER is a minecraft account attached to the USER
* a PROFILE is usually named after the PLAYER, and contains texture info

In addition to names, all three have different IDs, and it can be
tricky to distinguish which one you should use.


## Requirements

- [Python] 3.2+
- [requests](https://pypi.python.org/pypi/requests) for making the
  HTTP API calls
- [requests_cache](https://pypi.python.org/pypi/requests-cache)
  (optional feature) to enable caching HTTP API call results and
  avoiding rate-limit errors


## Author

Christopher O'Brien <obriencj@gmail.com>

If this project interests you, you can read about more of my hacks and
ideas [on my blog]

[on my blog]: http://obriencj.preoccupied.net


## License

This library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, see
<http://www.gnu.org/licenses/>.
