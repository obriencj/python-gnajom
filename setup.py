#! /usr/bin/env python2

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
gnajom - Python and command-line tools for working with Monjang's
public APIs.

:author: Christopher O'Brien  <obriencj@gmail.com>
:license: LGPL v.3
"""


from setuptools import setup


setup(name = "gnajom",
      version = "0.9.0",

      packages = [ "gnajom" ],

      author = "Christopher O'Brien",
      author_email = "obriencj@gmail.com",
      url = "https://github.com/obriencj/python-gnajom",
      license = "GNU Lesser General Public License v3",

      description = "Module and command line tools for working with"
      " Mojang's public APIs",

      provides = [ "gnajom" ],
      requires = [ "setuptools", "requests" ],

      zip_safe = True,

      classifiers = [ "Environment :: Console",
                      "Programming Language :: Python :: 2" ],

      entry_points = {
          "console_scripts": ['gnajom=gnajom.cli:main']
      })


#
# The end.
