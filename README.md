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

* `gnajom auth connect`
* `gnajom auth validate`
* `gnajom auth refresh`
* `gnajom auth invalidate`
* `gnajom auth show`
* `gnajom realm list`
* `gnajom realm backups REALM_ID`
* `gnajom realm download REALM_ID WORLD_SLOT`
* `gnajom realm info REALM_ID`
* `gnajom realm knock REALM_ID`
* `gnajom realm ping REALM_ID`
* `gnajom status`
* `gnajom statistics`
* `gnajom whoami`
* `gnajom player history PLAYER_NAME`
* `gnajom player info PLAYER_NAME`
* `gnajom profile lookup PLAYER_NAME ...`
* `gnajom profile info PROFILE_ID`
* `gnajom server ping SERVER_IP`
* `gnajom skin change URL`
* `gnajom skin upload FILE_NAME`
* `gnajom skin download`
* `gnajom skin reset`

Some distinctions are necessary for some of this to make sense:

* a USER is a mojang account, typically named by email address
* a PLAYER is a minecraft account attached to the USER
* a PROFILE is usually named after the PLAYER, and contains texture info

In addition to names, all three have different IDs, and it can be
tricky to distinguish which one you should use.


## Requirements

- [Python] 3.2+
- [requests](http://docs.python-requests.org/en/latest/) for HTTP calls
- [argparse](https://pypi.python.org/pypi/argparse) for composing the
  nested commands and options (included in Python 3.2+)


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
