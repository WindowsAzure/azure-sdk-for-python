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
    """An operation.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The operation name.
    :type name: str
    :param display: The operation display name.
    :type display: ~azure.mgmt.media.models.OperationDisplay
    :param origin: Origin of the operation.
    :type origin: str
    :param properties: Operation properties format.
    :type properties: ~azure.mgmt.media.models.MetricProperties
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'MetricProperties'},
    }

    def __init__(self, **kwargs):
        super(Operation, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display = kwargs.get('display', None)
        self.origin = kwargs.get('origin', None)
        self.properties = kwargs.get('properties', None)
