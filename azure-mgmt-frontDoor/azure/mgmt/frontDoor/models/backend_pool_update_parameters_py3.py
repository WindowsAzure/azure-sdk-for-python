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


class BackendPoolUpdateParameters(Model):
    """A collection of backends that can be routed to.

    :param backends: The set of backends for this pool
    :type backends: list[~azure.mgmt.frontdoor.models.Backend]
    :param load_balancing_settings: Load balancing settings for a backend pool
    :type load_balancing_settings: ~azure.mgmt.frontdoor.models.SubResource
    :param health_probe_settings: L7 health probe settings for a backend pool
    :type health_probe_settings: ~azure.mgmt.frontdoor.models.SubResource
    """

    _attribute_map = {
        'backends': {'key': 'backends', 'type': '[Backend]'},
        'load_balancing_settings': {'key': 'loadBalancingSettings', 'type': 'SubResource'},
        'health_probe_settings': {'key': 'healthProbeSettings', 'type': 'SubResource'},
    }

    def __init__(self, *, backends=None, load_balancing_settings=None, health_probe_settings=None, **kwargs) -> None:
        super(BackendPoolUpdateParameters, self).__init__(**kwargs)
        self.backends = backends
        self.load_balancing_settings = load_balancing_settings
        self.health_probe_settings = health_probe_settings
