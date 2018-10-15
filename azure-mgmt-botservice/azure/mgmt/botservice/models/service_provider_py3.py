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


class ServiceProvider(Model):
    """Service Provider Definition.

    :param properties: The Properties of a Service Provider Object
    :type properties: ~azure.mgmt.botservice.models.ServiceProviderProperties
    """

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'ServiceProviderProperties'},
    }

    def __init__(self, *, properties=None, **kwargs) -> None:
        super(ServiceProvider, self).__init__(**kwargs)
        self.properties = properties
