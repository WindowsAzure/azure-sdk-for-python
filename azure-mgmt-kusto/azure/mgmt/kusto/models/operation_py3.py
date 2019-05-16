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


class Operation(Model):
    """A REST API operation.

    :param name: The operation name. This is of the format
     {provider}/{resource}/{operation}.
    :type name: str
    :param display: The object that describes the operation.
    :type display: ~azure.mgmt.kusto.models.OperationDisplay
    :param origin: The intended executor of the operation.
    :type origin: str
    :param properties: Properties of the operation.
    :type properties: object
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'object'},
    }

    def __init__(self, *, name: str=None, display=None, origin: str=None, properties=None, **kwargs) -> None:
        super(Operation, self).__init__(**kwargs)
        self.name = name
        self.display = display
        self.origin = origin
        self.properties = properties
