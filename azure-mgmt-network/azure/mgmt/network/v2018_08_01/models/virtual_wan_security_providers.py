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


class VirtualWanSecurityProviders(Model):
    """Collection of SecurityProviders.

    :param supported_providers:
    :type supported_providers:
     list[~azure.mgmt.network.v2018_08_01.models.VirtualWanSecurityProvider]
    """

    _attribute_map = {
        'supported_providers': {'key': 'supportedProviders', 'type': '[VirtualWanSecurityProvider]'},
    }

    def __init__(self, **kwargs):
        super(VirtualWanSecurityProviders, self).__init__(**kwargs)
        self.supported_providers = kwargs.get('supported_providers', None)
