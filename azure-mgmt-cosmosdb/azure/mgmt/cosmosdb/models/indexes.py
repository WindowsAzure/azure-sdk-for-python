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

from msrest.serialization import Model


class Indexes(Model):
    """The indexes for the path.

    :param data_type: The datatype for which the indexing behavior is applied
     to. Possible values include: 'String', 'Number', 'Point', 'Polygon',
     'LineString', 'MultiPolygon'. Default value: "String" .
    :type data_type: str or ~azure.mgmt.cosmosdb.models.DataType
    :param precision: The precision of the index. -1 is maximum precision.
    :type precision: int
    :param kind: Indicates the type of index. Possible values include: 'Hash',
     'Range', 'Spatial'. Default value: "Hash" .
    :type kind: str or ~azure.mgmt.cosmosdb.models.IndexKind
    """

    _attribute_map = {
        'data_type': {'key': 'dataType', 'type': 'str'},
        'precision': {'key': 'precision', 'type': 'int'},
        'kind': {'key': 'kind', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Indexes, self).__init__(**kwargs)
        self.data_type = kwargs.get('data_type', "String")
        self.precision = kwargs.get('precision', None)
        self.kind = kwargs.get('kind', "Hash")
