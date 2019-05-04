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


class ResourceSkuRestrictionInfo(Model):
    """ResourceSkuRestrictionInfo.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar locations: Locations where the SKU is restricted
    :vartype locations: list[str]
    :ivar zones: List of availability zones where the SKU is restricted.
    :vartype zones: list[str]
    """

    _validation = {
        'locations': {'readonly': True},
        'zones': {'readonly': True},
    }

    _attribute_map = {
        'locations': {'key': 'locations', 'type': '[str]'},
        'zones': {'key': 'zones', 'type': '[str]'},
    }

    def __init__(self, **kwargs) -> None:
        super(ResourceSkuRestrictionInfo, self).__init__(**kwargs)
        self.locations = None
        self.zones = None
