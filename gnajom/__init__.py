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

The core package provides utilities to ease in constucting the individual
sevirces such as auth, realms, and users.

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


from abc import ABCMeta
from functools import partial, update_wrapper
from json import dumps
from requests import get, post, delete
from requests.cookies import RequestsCookieJar
from urllib.parse import urlencode


# seriously, how did people get along before requests? it's a shining
# gem among all python modules. get, put, cookies, headers, multi-part
# form encoding, url form encoding, all easily accessible.


__all__ = (
    "APIHost", "APICache", "usecache",
    "enable_cache", "disable_cache", "cache_is_enabled", )


class APIHost(object):
    """
    Lightweight wrapper for RESTful JSON calls
    """

    def __init__(self, hosturi, apicache=None, debug_hook=None):

        # if an empty hosturi has gotten this far in the API,
        # something is screwed up.
        assert(hosturi)

        self._host = hosturi
        self.apicache = apicache
        self.cookies = RequestsCookieJar()
        self.headers = {}
        self.debug_hook = debug_hook


    def get(self, endpoint):
        """
        Trigger an API endpoint on the host via an HTTP GET. Any JSON
        results will be parsed and returned.
        """

        assert(endpoint)

        resp = get(self._host + endpoint,
                   cookies=self.cookies, headers=self.headers)

        if self.debug_hook:
            self.debug_hook(resp)
        resp.raise_for_status()

        return resp.json() if len(resp.content) else None


    def delete(self, endpoint):
        """
        Trigger an API endpoint on the host via an HTTP DELETE. Any JSON
        results will be parsed and returned.
        """

        assert(endpoint)

        resp = delete(self._host + endpoint,
                      cookies=self.cookies, headers=self.headers)

        if self.debug_hook:
            self.debug_hook(resp)
        resp.raise_for_status()

        return resp.json() if len(resp.content) else None


    def post(self, endpoint, payload):
        """
        Trigger an API endpoint on the host via an HTTP POST, sending
        payload represented as a JSON. Any JSON results will be parsed
        and returned.
        """

        assert(endpoint)

        data = dumps(payload)

        headers = self.headers.copy()
        headers["Content-Type"] = "application/json"

        resp = post(self._host + endpoint, data,
                    cookies=self.cookies, headers=headers)

        if self.debug_hook:
            self.debug_hook(resp)
        resp.raise_for_status()

        return resp.json() if len(resp.content) else None


    def post_form(self, endpoint, payload):
        """
        Trigger an API endpoint on the host via an HTTP POST, sending
        payload represented as multipart form data. Any JSON results
        will be parsed and returned.
        """

        assert(endpoint)

        # requests is smart enough to update the Content-Type header
        # when the files= argument is specified
        resp = post(self._host + endpoint, files=payload,
                    cookies=self.cookies, headers=self.headers)

        if self.debug_hook:
            self.debug_hook(resp)
        resp.raise_for_status()

        return resp.json() if len(resp.content) else None


    def post_encoded(self, endpoint, payload):
        """
        Trigger an API endpoint on the host via an HTTP POST, sending
        payload represented as urlencoded form data. Any JSON results
        will be parsed and returned.
        """

        assert(endpoint)

        data = urlencode(payload)

        headers = self.headers.copy()
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        resp = post(self._host + endpoint, data,
                    cookies=self.cookies, headers=self.headers)

        if self.debug_hook:
            self.debug_hook(resp)
        resp.raise_for_status()

        return resp.json() if len(resp.content) else None


class GnajomAPI(object):
    """
    Parent class for various API instances. Subclasses may decorate
    their methods with @usecache to optionally enable local caching of
    requests.
    """

    __metaclass__ = ABCMeta

    def __init__(self, auth, host, apicache=None, debug_hook=None):
        assert(auth is not None)
        assert(host is not None)

        self.auth = auth
        self.api = APIHost(host, apicache, debug_hook)


def usecache(func):
    """
    Decorator for methods on a GnajomAPI instance
    """

    def wrapper(self, *args, **kwds):
        nocache = kwds.get("nocache", False)

        if self.api.apicache and not nocache:
            with self.api.apicache:
                result = func(self, *args, **kwds)
        else:
            result = func(self, *args, **kwds)
        return result

    update_wrapper(wrapper, func)
    return wrapper


_CACHE_INSTALLED = False


def cache_is_enabled():
    """
    Returns True if the global cache has been enabled via the
    `enable_cache` function.
    """

    return _CACHE_INSTALLED


def enable_cache(fileprefix, cachetype, expiry):
    """
    If the requests_cache package is available, install a cache and
    begin using it globally. Returns True if caching was successfully
    enabled, and False otherwise (failed to enable, or enabled
    already)
    """

    global _CACHE_INSTALLED

    if _CACHE_INSTALLED:
        return False

    try:
        from requests_cache import install_cache
        from requests_cache.core import remove_expired_responses

        install_cache(fileprefix, cachetype, expire_after=expiry)
        remove_expired_responses()

    except ImportError:
        return False

    else:
        _CACHE_INSTALLED = True
        return True


def disable_cache():
    """
    If the requests_cache package is available, uninstall the existing
    installed cache. Returns True if disable happened.
    """

    global _CACHE_INSTALLED

    if not _CACHE_INSTALLED:
        return False

    try:
        from requests_cache import uninstall_cache
        uninstall_cache()

    except ImportError:
        return False

    else:
        _CACHE_INSTALLED = False
        return True


class APICache(object):
    """
    A Context Manager that will enable caching on enter, and disable
    it when the context exits. Trimming/cleanup of expired entries
    occurs on enter.

    Can be reused repeatedly.

    This can be used even if requests_cache is not installed, it
    simply won't have any caching effect.
    """

    def __init__(self, fileprefix, cachetype, expiry):
        self.enable = partial(enable_cache, fileprefix, cachetype, expiry)
        self.disable = disable_cache
        self.working = False


    def __enter__(self):
        # enable the cache, and remember if we were able to
        self.working = self.enable()
        return self


    def __exit__(self, _exc_type, _exc_val, _exc_trace):
        # we only want to disable the cache if we were the ones that
        # enabled it in the first place.
        if self.working:
            self.disable()
            self.working = False


#
# The end.
