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


class CheckSkuAvailabilityResultList(Model):
    """Check SKU availability result list.

    :param value: Check SKU availability result list.
    :type value:
     list[~azure.mgmt.cognitiveservices.models.CheckSkuAvailabilityResult]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[CheckSkuAvailabilityResult]'},
    }

    def __init__(self, **kwargs):
        super(CheckSkuAvailabilityResultList, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
