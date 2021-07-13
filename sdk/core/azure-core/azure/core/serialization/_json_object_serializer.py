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
import logging
from typing import cast, IO, BinaryIO, Optional, Any, Type
import json

from ._object_serializer import ObjectSerializer


_LOGGER = logging.getLogger(__name__)


class JsonObjectSerializer(ObjectSerializer):

    def __init__(self, **kwargs):
        """A JSON serializer using json lib from Python.

        :keyword serializer_kwargs: Kwargs passed so json.dump at each serialization
        :paramtype dict[str, any]:
        :keyword deserializer_kwargs: Kwargs passed so json.load(s) at each deserialization
        :paramtype dict[str, any]:

        """
        self.serializer_kwargs = kwargs.pop("serializer_kwargs", {})
        self.deserializer_kwargs = kwargs.pop("deserializer_kwargs", {})

    def serialize(
        self,
        stream,  # type: BinaryIO
        value,  # type: ObjectType
        schema=None,  # type: Optional[Any]
    ):
        # type: (...) -> None
        """Convert the provided value to it's binary representation and write it to the stream.

        Schema is not supported by the JSON serializer

        :param stream: A stream of bytes or bytes directly
        :type stream: BinaryIO
        :param value: An object to serialize
        :param schema: Schema is not supported in the JSON serializer
        """
        if schema:
            _LOGGER.warning("Schema is not supported by the JSON serializer")

        bytes_value = json.dumps(value, **self.serializer_kwargs).encode("utf-8")
        stream.write(bytes_value)

    def deserialize(
        self,
        data,  # type: Union[bytes, BinaryIO]
        return_type=None,  # type: Optional[Type[ObjectType]]
    ):
        # type: (...) -> ObjectType
        """Read the binary representation into a specific type.

        Return type is not supported by the JSON serializer

        :param data: A stream of bytes or bytes directly
        :type data: BinaryIO or bytes
        :param return_type: Return type is not supported in the JSON serializer.
        :returns: An instanciated object
        :rtype: ObjectType
        """
        if return_type:
            _LOGGER.warning("Schema is not supported by the JSON serializer")

        if hasattr(data, 'read'):
            # Assume a stream
            data = cast(IO, data).read()

        if isinstance(data, bytes):
            data_as_str = data.decode(encoding='utf-8-sig')
        else:
            # Explain to mypy the correct type.
            data_as_str = cast(str, data)

        return json.loads(data_as_str, **self.deserializer_kwargs)
