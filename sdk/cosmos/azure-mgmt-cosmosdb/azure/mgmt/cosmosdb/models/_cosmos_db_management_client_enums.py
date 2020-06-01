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


class DatabaseAccountKind(str, Enum):

    global_document_db = "GlobalDocumentDB"
    mongo_db = "MongoDB"
    parse = "Parse"


class DatabaseAccountOfferType(str, Enum):

    standard = "Standard"


class DefaultConsistencyLevel(str, Enum):

    eventual = "Eventual"
    session = "Session"
    bounded_staleness = "BoundedStaleness"
    strong = "Strong"
    consistent_prefix = "ConsistentPrefix"


class ConnectorOffer(str, Enum):

    small = "Small"


class PublicNetworkAccess(str, Enum):

    enabled = "Enabled"
    disabled = "Disabled"


class IndexingMode(str, Enum):

    consistent = "Consistent"
    lazy = "Lazy"
    none = "None"


class DataType(str, Enum):

    string = "String"
    number = "Number"
    point = "Point"
    polygon = "Polygon"
    line_string = "LineString"
    multi_polygon = "MultiPolygon"


class IndexKind(str, Enum):

    hash = "Hash"
    range = "Range"
    spatial = "Spatial"


class CompositePathSortOrder(str, Enum):

    ascending = "Ascending"
    descending = "Descending"


class SpatialType(str, Enum):

    point = "Point"
    line_string = "LineString"
    polygon = "Polygon"
    multi_polygon = "MultiPolygon"


class PartitionKind(str, Enum):

    hash = "Hash"
    range = "Range"


class ConflictResolutionMode(str, Enum):

    last_writer_wins = "LastWriterWins"
    custom = "Custom"


class TriggerType(str, Enum):

    pre = "Pre"
    post = "Post"


class TriggerOperation(str, Enum):

    all = "All"
    create = "Create"
    update = "Update"
    delete = "Delete"
    replace = "Replace"


class KeyKind(str, Enum):

    primary = "primary"
    secondary = "secondary"
    primary_readonly = "primaryReadonly"
    secondary_readonly = "secondaryReadonly"


class UnitType(str, Enum):

    count = "Count"
    bytes = "Bytes"
    seconds = "Seconds"
    percent = "Percent"
    count_per_second = "CountPerSecond"
    bytes_per_second = "BytesPerSecond"
    milliseconds = "Milliseconds"


class PrimaryAggregationType(str, Enum):

    none = "None"
    average = "Average"
    total = "Total"
    minimum = "Minimum"
    maximum = "Maximum"
    last = "Last"
