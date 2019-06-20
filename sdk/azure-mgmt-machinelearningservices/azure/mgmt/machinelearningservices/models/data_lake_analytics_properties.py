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


class DataLakeAnalyticsProperties(Model):
    """DataLakeAnalyticsProperties.

    :param data_lake_store_account_name: DataLake Store Account Name
    :type data_lake_store_account_name: str
    """

    _attribute_map = {
        'data_lake_store_account_name': {'key': 'dataLakeStoreAccountName', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(DataLakeAnalyticsProperties, self).__init__(**kwargs)
        self.data_lake_store_account_name = kwargs.get('data_lake_store_account_name', None)
