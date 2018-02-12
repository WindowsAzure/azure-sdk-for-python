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


class AutomationAccountUpdateParameters(Model):
    """The parameters supplied to the update automation account operation.

    :param sku: Gets or sets account SKU.
    :type sku: ~azure.mgmt.automation.models.Sku
    :param name: Gets or sets the name of the resource.
    :type name: str
    :param location: Gets or sets the location of the resource.
    :type location: str
    :param tags: Gets or sets the tags attached to the resource.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'sku': {'key': 'properties.sku', 'type': 'Sku'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, sku=None, name=None, location=None, tags=None):
        super(AutomationAccountUpdateParameters, self).__init__()
        self.sku = sku
        self.name = name
        self.location = location
        self.tags = tags
