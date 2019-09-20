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


class PeeringLocationPropertiesExchange(Model):
    """The properties that define an exchange peering location.

    :param peering_facilities: The list of exchange peering facilities at the
     peering location.
    :type peering_facilities:
     list[~azure.mgmt.peering.models.ExchangePeeringFacility]
    """

    _attribute_map = {
        'peering_facilities': {'key': 'peeringFacilities', 'type': '[ExchangePeeringFacility]'},
    }

    def __init__(self, *, peering_facilities=None, **kwargs) -> None:
        super(PeeringLocationPropertiesExchange, self).__init__(**kwargs)
        self.peering_facilities = peering_facilities
