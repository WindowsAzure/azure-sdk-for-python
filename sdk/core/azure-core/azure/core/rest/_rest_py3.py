# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------
import copy
import asyncio
import cgi
import collections
import collections.abc
from json import loads
from typing import (
    Any,
    AsyncIterable,
    AsyncIterator,
    Dict,
    Iterable, Iterator,
    Optional,
    Type,
    Union,
)
from abc import abstractmethod

from azure.core.exceptions import HttpResponseError

from .._utils import _case_insensitive_dict

from ._helpers import (
    ParamsType,
    FilesType,
    HeadersType,
    cast,
    lookup_encoding,
    parse_lines_from_text,
    set_json_body,
    set_multipart_body,
    set_urlencoded_body,
    format_parameters,
    to_pipeline_transport_request_helper,
    from_pipeline_transport_request_helper,
)
from ._helpers_py3 import set_content_body
from ..exceptions import ResponseNotReadError

ContentType = Union[str, bytes, Iterable[bytes], AsyncIterable[bytes]]

class _AsyncContextManager(collections.abc.Awaitable):

    def __init__(self, wrapped: collections.abc.Awaitable):
        super().__init__()
        self.wrapped = wrapped
        self.response = None

    def __await__(self):
        return self.wrapped.__await__()

    async def __aenter__(self):
        self.response = await self
        return self.response

    async def __aexit__(self, *args):
        await self.response.__aexit__(*args)

    async def close(self):
        await self.response.close()

################################## CLASSES ######################################

class HttpRequest:
    """**Provisional** object that represents an HTTP request.

    **This object is provisional**, meaning it may be changed.

    :param str method: HTTP method (GET, HEAD, etc.)
    :param str url: The url for your request
    :keyword mapping params: Query parameters to be mapped into your URL. Your input
     should be a mapping of query name to query value(s).
    :keyword mapping headers: HTTP headers you want in your request. Your input should
     be a mapping of header name to header value.
    :keyword any json: A JSON serializable object. We handle JSON-serialization for your
     object, so use this for more complicated data structures than `data`.
    :keyword content: Content you want in your request body. Think of it as the kwarg you should input
     if your data doesn't fit into `json`, `data`, or `files`. Accepts a bytes type, or a generator
     that yields bytes.
    :paramtype content: str or bytes or iterable[bytes] or asynciterable[bytes]
    :keyword dict data: Form data you want in your request body. Use for form-encoded data, i.e.
     HTML forms.
    :keyword mapping files: Files you want to in your request body. Use for uploading files with
     multipart encoding. Your input should be a mapping of file name to file content.
     Use the `data` kwarg in addition if you want to include non-file data files as part of your request.
    :ivar str url: The URL this request is against.
    :ivar str method: The method type of this request.
    :ivar mapping headers: The HTTP headers you passed in to your request
    :ivar any content: The content passed in for the request
    """

    def __init__(
        self,
        method: str,
        url: str,
        *,
        params: Optional[ParamsType] = None,
        headers: Optional[HeadersType] = None,
        json: Any = None,
        content: Optional[ContentType] = None,
        data: Optional[dict] = None,
        files: Optional[FilesType] = None,
        **kwargs
    ):
        self.url = url
        self.method = method

        if params:
            self.url = format_parameters(self.url, params)
        self._files = None
        self._data = None  # type: Any

        default_headers = self._set_body(
            content=content,
            data=data,
            files=files,
            json=json,
        )
        self.headers = _case_insensitive_dict(default_headers)
        self.headers.update(headers or {})

        if kwargs:
            raise TypeError(
                "You have passed in kwargs '{}' that are not valid kwargs.".format(
                    "', '".join(list(kwargs.keys()))
                )
            )

    def _set_body(
        self,
        content: Optional[ContentType],
        data: Optional[dict],
        files: Optional[FilesType],
        json: Any,
    ) -> HeadersType:
        """Sets the body of the request, and returns the default headers
        """
        default_headers = {}  # type: HeadersType
        if data is not None and not isinstance(data, dict):
            # should we warn?
            content = data
        if content is not None:
            default_headers, self._data = set_content_body(content)
            return default_headers
        if json is not None:
            default_headers, self._data = set_json_body(json)
            return default_headers
        if files:
            default_headers, self._files = set_multipart_body(files)
        if data:
            default_headers, self._data = set_urlencoded_body(data)
        if files and data:
            # little hacky, but for files we don't send a content type with
            # boundary so requests / aiohttp etc deal with it
            default_headers.pop("Content-Type")
        return default_headers

    @property
    def content(self) -> Any:
        """Get's the request's content

        :return: The request's content
        :rtype: any
        """
        return self._data or self._files

    def __repr__(self) -> str:
        return "<HttpRequest [{}], url: '{}'>".format(
            self.method, self.url
        )

    def __deepcopy__(self, memo=None) -> "HttpRequest":
        try:
            request = HttpRequest(
                method=self.method,
                url=self.url,
                headers=self.headers,
            )
            request._data = copy.deepcopy(self._data, memo)
            request._files = copy.deepcopy(self._files, memo)
            return request
        except (ValueError, TypeError):
            return copy.copy(self)

    def _to_pipeline_transport_request(self):
        return to_pipeline_transport_request_helper(self)

    @classmethod
    def _from_pipeline_transport_request(cls, pipeline_transport_request):
        return from_pipeline_transport_request_helper(cls, pipeline_transport_request)

class _HttpResponseBase:  # pylint: disable=too-many-instance-attributes

    def __init__(
        self,
        *,
        request: HttpRequest,
        internal_response,
        **kwargs  # pylint: disable=unused-argument
    ):
        self.request = request
        self.internal_response = internal_response
        self.status_code = None
        self.headers = {}  # type: HeadersType
        self.reason = None
        self.is_closed = False
        self.is_stream_consumed = False
        self._num_bytes_downloaded = 0
        self.content_type = None
        self._connection_data_block_size = None
        self._json = None  # this is filled in ContentDecodePolicy, when we deserialize
        self._content = None

    @property
    def url(self) -> str:
        """Returns the URL that resulted in this response"""
        return self.request.url

    def _get_charset_encoding(self) -> Optional[str]:
        content_type = self.headers.get("Content-Type")

        if not content_type:
            return None
        _, params = cgi.parse_header(content_type)
        encoding = params.get('charset') # -> utf-8
        if encoding is None or not lookup_encoding(encoding):
            return None
        return encoding

    def _get_content(self):
        """Return the internal response's content"""
        return self._content

    def _set_content(self, val):
        """Set the internal response's content"""
        self._content = val

    def _has_content(self):
        """How to check if your internal response has content"""
        return self._content is not None

    @property
    def encoding(self) -> Optional[str]:
        """Returns the response encoding. By default, is specified
        by the response Content-Type header.
        """
        try:
            return self._encoding
        except AttributeError:
            return self._get_charset_encoding()

    @encoding.setter
    def encoding(self, value: str) -> None:
        """Sets the response encoding"""
        self._encoding = value

    @property
    def text(self) -> str:
        """Returns the response body as a string"""
        encoding = self.encoding
        if encoding == "utf-8" or encoding is None:
            encoding = "utf-8-sig"
        return self.content.decode(encoding)

    @property
    def num_bytes_downloaded(self) -> int:
        """See how many bytes of your stream response have been downloaded"""
        return self._num_bytes_downloaded

    def json(self) -> Any:
        """Returns the whole body as a json object.

        :return: The JSON deserialized response body
        :rtype: any
        :raises json.decoder.JSONDecodeError or ValueError (in python 2.7) if object is not JSON decodable:
        """
        if not self._has_content():
            raise ResponseNotReadError()
        if not self._json:
            self._json = loads(self.text)
        return self._json

    def raise_for_status(self) -> None:
        """Raises an HttpResponseError if the response has an error status code.

        If response is good, does nothing.
        """
        if cast(int, self.status_code) >= 400:
            raise HttpResponseError(response=self)

    @property
    def content(self) -> bytes:
        """Return the response's content in bytes."""
        if not self._has_content():
            raise ResponseNotReadError()
        return cast(bytes, self._get_content())

class HttpResponse(_HttpResponseBase):
    """**Provisional** object that represents an HTTP response.

    **This object is provisional**, meaning it may be changed.

    :keyword request: The request that resulted in this response.
    :paramtype request: ~azure.core.rest.HttpRequest
    :keyword internal_response: The object returned from the HTTP library.
    :ivar int status_code: The status code of this response
    :ivar mapping headers: The response headers
    :ivar str reason: The reason phrase for this response
    :ivar bytes content: The response content in bytes.
    :ivar str url: The URL that resulted in this response
    :ivar str encoding: The response encoding. Is settable, by default
     is the response Content-Type header
    :ivar str text: The response body as a string.
    :ivar request: The request that resulted in this response.
    :vartype request: ~azure.core.rest.HttpRequest
    :ivar internal_response: The object returned from the HTTP library.
    :ivar str content_type: The content type of the response
    :ivar bool is_closed: Whether the network connection has been closed yet
    :ivar bool is_stream_consumed: When getting a stream response, checks
     whether the stream has been fully consumed
    :ivar int num_bytes_downloaded: The number of bytes in your stream that
     have been downloaded
    """

    def __enter__(self) -> "HttpResponse":
        return self

    def close(self) -> None:
        """Close the response

        :return: None
        :rtype: None
        """
        self.is_closed = True
        self.internal_response.close()

    def __exit__(self, *args) -> None:
        self.is_closed = True
        self.internal_response.__exit__(*args)

    def read(self) -> bytes:
        """Read the response's bytes.

        :return: The read in bytes
        :rtype: bytes
        """
        if not self._has_content():
            self._set_content(b"".join(self.iter_bytes()))
        return self.content

    def iter_raw(self, chunk_size: Optional[int] = None) -> Iterator[bytes]:
        """Iterates over the response's bytes. Will not decompress in the process

        :param int chunk_size: The maximum size of each chunk iterated over.
        :return: An iterator of bytes from the response
        :rtype: Iterator[str]
        """
        raise NotImplementedError()

    def iter_bytes(self, chunk_size: Optional[int] = None) -> Iterator[bytes]:
        """Iterates over the response's bytes. Will decompress in the process

        :param int chunk_size: The maximum size of each chunk iterated over.
        :return: An iterator of bytes from the response
        :rtype: Iterator[str]
        """
        raise NotImplementedError()

    def iter_text(self, chunk_size: int = None) -> Iterator[str]:
        """Iterates over the text in the response.

        :param int chunk_size: The maximum size of each chunk iterated over.
        :return: An iterator of string. Each string chunk will be a text from the response
        :rtype: Iterator[str]
        """
        for byte in self.iter_bytes(chunk_size):
            text = byte.decode(self.encoding or "utf-8")
            yield text

    def iter_lines(self, chunk_size: int = None) -> Iterator[str]:
        """Iterates over the lines in the response.

        :param int chunk_size: The maximum size of each chunk iterated over.
        :return: An iterator of string. Each string chunk will be a line from the response
        :rtype: Iterator[str]
        """
        for text in self.iter_text(chunk_size):
            lines = parse_lines_from_text(text)
            for line in lines:
                yield line

    def __repr__(self) -> str:
        content_type_str = (
            ", Content-Type: {}".format(self.content_type) if self.content_type else ""
        )
        return "<HttpResponse: {} {}{}>".format(
            self.status_code, self.reason, content_type_str
        )

class AsyncHttpResponse(_HttpResponseBase):
    """**Provisional** object that represents an Async HTTP response.

    **This object is provisional**, meaning it may be changed.

    :keyword request: The request that resulted in this response.
    :paramtype request: ~azure.core.rest.HttpRequest
    :keyword internal_response: The object returned from the HTTP library.
    :ivar int status_code: The status code of this response
    :ivar mapping headers: The response headers
    :ivar str reason: The reason phrase for this response
    :ivar bytes content: The response content in bytes.
    :ivar str url: The URL that resulted in this response
    :ivar str encoding: The response encoding. Is settable, by default
     is the response Content-Type header
    :ivar str text: The response body as a string.
    :ivar request: The request that resulted in this response.
    :vartype request: ~azure.core.rest.HttpRequest
    :ivar internal_response: The object returned from the HTTP library.
    :ivar str content_type: The content type of the response
    :ivar bool is_closed: Whether the network connection has been closed yet
    :ivar bool is_stream_consumed: When getting a stream response, checks
     whether the stream has been fully consumed
    :ivar int num_bytes_downloaded: The number of bytes in your stream that
     have been downloaded
    """

    async def read(self) -> bytes:
        """Read the response's bytes into memory.

        :return: The response's bytes
        :rtype: bytes
        """
        if not self._has_content():
            parts = []
            async for part in self.iter_bytes():  # type: ignore
                parts.append(part)
            self._set_content(b"".join(parts))
        return self._get_content()

    async def iter_raw(self, chunk_size: int = None) -> AsyncIterator[bytes]:
        """Asynchronously iterates over the response's bytes. Will not decompress in the process

        :param int chunk_size: The maximum size of each chunk iterated over.
        :return: An async iterator of bytes from the response
        :rtype: AsyncIterator[bytes]
        """
        # If you don't have a yield in an AsyncIterator function,
        # mypy will think it's a coroutine
        # see here https://github.com/python/mypy/issues/5385#issuecomment-407281656
        # So, adding this weird yield thing
        for _ in []:
            yield _
        raise NotImplementedError()

    async def iter_bytes(self, chunk_size: int = None) -> AsyncIterator[bytes]:
        """Asynchronously iterates over the response's bytes. Will decompress in the process

        :param int chunk_size: The maximum size of each chunk iterated over.
        :return: An async iterator of bytes from the response
        :rtype: AsyncIterator[bytes]
        """
        # If you don't have a yield in an AsyncIterator function,
        # mypy will think it's a coroutine
        # see here https://github.com/python/mypy/issues/5385#issuecomment-407281656
        # So, adding this weird yield thing
        for _ in []:
            yield _
        raise NotImplementedError()

    async def iter_text(self, chunk_size: int = None) -> AsyncIterator[str]:
        """Asynchronously iterates over the text in the response.

        :param int chunk_size: The maximum size of each chunk iterated over.
        :return: An async iterator of string. Each string chunk will be a text from the response
        :rtype: AsyncIterator[str]
        """
        async for byte in self.iter_bytes(chunk_size):  # type: ignore
            text = byte.decode(self.encoding or "utf-8")
            yield text

    async def iter_lines(self, chunk_size: int = None) -> AsyncIterator[str]:
        """Asynchronously iterates over the lines in the response.

        :param int chunk_size: The maximum size of each chunk iterated over.
        :return: An async iterator of string. Each string chunk will be a line from the response
        :rtype: AsyncIterator[str]
        """
        async for text in self.iter_text(chunk_size):
            lines = parse_lines_from_text(text)
            for line in lines:
                yield line

    async def close(self) -> None:
        """Close the response.

        :return: None
        :rtype: None
        """
        self.is_closed = True
        self.internal_response.close()
        await asyncio.sleep(0)

    async def __aexit__(self, *args) -> None:
        self.is_closed = True
        await self.internal_response.__aexit__(*args)

    def __repr__(self) -> str:
        content_type_str = (
            ", Content-Type: {}".format(self.content_type) if self.content_type else ""
        )
        return "<AsyncHttpResponse: {} {}{}>".format(
            self.status_code, self.reason, content_type_str
        )
