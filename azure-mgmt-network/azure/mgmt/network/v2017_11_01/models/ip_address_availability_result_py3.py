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


class IPAddressAvailabilityResult(Model):
    """Response for CheckIPAddressAvailability API service call.

    :param available: Private IP address availability.
    :type available: bool
    :param available_ip_addresses: Contains other available private IP
     addresses if the asked for address is taken.
    :type available_ip_addresses: list[str]
    """

    _attribute_map = {
        'available': {'key': 'available', 'type': 'bool'},
        'available_ip_addresses': {'key': 'availableIPAddresses', 'type': '[str]'},
    }

    def __init__(self, *, available: bool=None, available_ip_addresses=None, **kwargs) -> None:
        super(IPAddressAvailabilityResult, self).__init__(**kwargs)
        self.available = available
        self.available_ip_addresses = available_ip_addresses
