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


class SkuLocationInfoItem(Model):
    """The locations and zones info for SKU.

    All required parameters must be populated in order to send to Azure.

    :param location: Required. The available location of the SKU.
    :type location: str
    :param zones: The available zone of the SKU.
    :type zones: list[str]
    """

    _validation = {
        'location': {'required': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'zones': {'key': 'zones', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(SkuLocationInfoItem, self).__init__(**kwargs)
        self.location = kwargs.get('location', None)
        self.zones = kwargs.get('zones', None)
