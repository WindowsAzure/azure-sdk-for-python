# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from enum import Enum


class ResultFormat(str, Enum):

    table = "table"
    object_array = "objectArray"


class FacetSortOrder(str, Enum):

    asc = "asc"
    desc = "desc"


class ResultTruncated(str, Enum):

    true = "true"
    false = "false"


class ColumnDataType(str, Enum):

    string = "string"
    integer = "integer"
    number = "number"
    boolean = "boolean"
    object_enum = "object"


class ChangeType(str, Enum):

    create = "Create"
    update = "Update"
    delete = "Delete"


class ChangeCategory(str, Enum):

    user = "User"
    system = "System"


class PropertyChangeType(str, Enum):

    insert = "Insert"
    update = "Update"
    remove = "Remove"
