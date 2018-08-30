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


class AvailableDelegationsResult(Model):
    """AvailableDelegationsResult.

    :param value: An array of available delegations.
    :type value:
     list[~azure.mgmt.network.v2018_08_01.models.AvailableDelegation]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[AvailableDelegation]'},
    }

    def __init__(self, **kwargs):
        super(AvailableDelegationsResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
