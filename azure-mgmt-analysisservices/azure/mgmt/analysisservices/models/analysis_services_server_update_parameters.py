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


class AnalysisServicesServerUpdateParameters(Model):
    """Provision request specification.

    :param sku: The SKU of the Analysis Services resource.
    :type sku: :class:`ResourceSku
     <azure.mgmt.analysisservices.models.ResourceSku>`
    :param tags: Key-value pairs of additional provisioning properties.
    :type tags: dict
    :param as_administrators:
    :type as_administrators: :class:`ServerAdministrators
     <azure.mgmt.analysisservices.models.ServerAdministrators>`
    """

    _attribute_map = {
        'sku': {'key': 'sku', 'type': 'ResourceSku'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'as_administrators': {'key': 'properties.asAdministrators', 'type': 'ServerAdministrators'},
    }

    def __init__(self, sku=None, tags=None, as_administrators=None):
        self.sku = sku
        self.tags = tags
        self.as_administrators = as_administrators
