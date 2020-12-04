# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


class BaseObject:
    __slots__ = ()

    def __repr__(self):
        tmp = {}

        for key in self.__slots__:
            data = getattr(self, key, None)
            if isinstance(data, BaseObject):
                tmp[key] = repr(data)
            else:
                tmp[key] = data

        return repr(tmp)


class ExporterOptions(BaseObject):
    """Configuration for Azure Exporters.

    :param connection_string: Azure Connection String.
    :type connection_string: str
    """

    __slots__ = (
        "connection_string",
    )

    def __init__(
        self,
        connection_string: str = None
    ):  # type: (...) -> None
        self.connection_string = connection_string
