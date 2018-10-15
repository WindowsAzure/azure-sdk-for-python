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


class BgpPeerStatusListResult(Model):
    """Response for list BGP peer status API service call.

    :param value: List of BGP peers
    :type value: list[~azure.mgmt.network.v2018_07_01.models.BgpPeerStatus]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[BgpPeerStatus]'},
    }

    def __init__(self, **kwargs):
        super(BgpPeerStatusListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
