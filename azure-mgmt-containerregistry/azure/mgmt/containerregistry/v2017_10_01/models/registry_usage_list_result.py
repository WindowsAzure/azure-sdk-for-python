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


class RegistryUsageListResult(Model):
    """The result of a request to get container registry quota usages.

    :param value: The list of container registry quota usages.
    :type value:
     list[~azure.mgmt.containerregistry.v2017_10_01.models.RegistryUsage]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[RegistryUsage]'},
    }

    def __init__(self, **kwargs):
        super(RegistryUsageListResult, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)
