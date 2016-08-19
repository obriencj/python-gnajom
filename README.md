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


## Requirements

- [Python] 2.6 or later (no support for Python 3, because I don't care)
- [requests](http://docs.python-requests.org/en/latest/)
- [argparse](https://pypi.python.org/pypi/argparse)


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
