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


class AzureMetricsData(Model):
    """AzureMetricsData.

    :param base_data:
    :type base_data: ~azure.monitor.models.AzureMetricsBaseData
    """

    _attribute_map = {
        'base_data': {'key': 'BaseData', 'type': 'AzureMetricsBaseData'},
    }

    def __init__(self, *, base_data=None, **kwargs) -> None:
        super(AzureMetricsData, self).__init__(**kwargs)
        self.base_data = base_data
