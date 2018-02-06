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


class ComputeOperationListResult(Model):
    """The List Compute Operation operation response.

    :param value: The list of compute operations
    :type value:
     list[~azure.mgmt.compute.v2017_12_01.models.ComputeOperationValue]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ComputeOperationValue]'},
    }

    def __init__(self, value=None):
        super(ComputeOperationListResult, self).__init__()
        self.value = value
