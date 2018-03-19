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


class CreateSignalRResourceRequest(Model):
    """Parameters for SignalR service create/update operation.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. The location of the SignalR service.
    :type location: str
    :param tags: A list of key value pairs that describe the resource.
    :type tags: dict[str, str]
    :param sku: Required. The billing information of the resource.(e.g. basic
     vs. standard)
    :type sku: ~azure.mgmt.signalr.models.ResourceSku
    :param properties: Required. Settings used to provision or configure the
     resource
    :type properties:
     ~azure.mgmt.signalr.models.CreateSignalRResourceRequestProperties
    """

    _validation = {
        'location': {'required': True},
        'sku': {'required': True},
        'properties': {'required': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'ResourceSku'},
        'properties': {'key': 'properties', 'type': 'CreateSignalRResourceRequestProperties'},
    }

    def __init__(self, **kwargs):
        super(CreateSignalRResourceRequest, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)
        self.sku = kwargs.get('sku', None)
        self.properties = kwargs.get('properties', None)
