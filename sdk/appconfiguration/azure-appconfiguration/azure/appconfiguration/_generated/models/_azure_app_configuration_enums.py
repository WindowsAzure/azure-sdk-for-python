# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class Enum4(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    KEY = "key"
    LABEL = "label"
    CONTENT_TYPE = "content_type"
    VALUE = "value"
    LAST_MODIFIED = "last_modified"
    TAGS = "tags"
    LOCKED = "locked"
    ETAG = "etag"

class Enum5(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    KEY = "key"
    LABEL = "label"
    CONTENT_TYPE = "content_type"
    VALUE = "value"
    LAST_MODIFIED = "last_modified"
    TAGS = "tags"
    LOCKED = "locked"
    ETAG = "etag"

class Get6ItemsItem(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    KEY = "key"
    LABEL = "label"
    CONTENT_TYPE = "content_type"
    VALUE = "value"
    LAST_MODIFIED = "last_modified"
    TAGS = "tags"
    LOCKED = "locked"
    ETAG = "etag"

class Get7ItemsItem(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    KEY = "key"
    LABEL = "label"
    CONTENT_TYPE = "content_type"
    VALUE = "value"
    LAST_MODIFIED = "last_modified"
    TAGS = "tags"
    LOCKED = "locked"
    ETAG = "etag"

class Head6ItemsItem(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    KEY = "key"
    LABEL = "label"
    CONTENT_TYPE = "content_type"
    VALUE = "value"
    LAST_MODIFIED = "last_modified"
    TAGS = "tags"
    LOCKED = "locked"
    ETAG = "etag"

class Head7ItemsItem(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):

    KEY = "key"
    LABEL = "label"
    CONTENT_TYPE = "content_type"
    VALUE = "value"
    LAST_MODIFIED = "last_modified"
    TAGS = "tags"
    LOCKED = "locked"
    ETAG = "etag"
