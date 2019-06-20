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


class DatabricksProperties(Model):
    """DatabricksProperties.

    :param databricks_access_token: Databricks access token
    :type databricks_access_token: str
    """

    _attribute_map = {
        'databricks_access_token': {'key': 'databricksAccessToken', 'type': 'str'},
    }

    def __init__(self, *, databricks_access_token: str=None, **kwargs) -> None:
        super(DatabricksProperties, self).__init__(**kwargs)
        self.databricks_access_token = databricks_access_token
