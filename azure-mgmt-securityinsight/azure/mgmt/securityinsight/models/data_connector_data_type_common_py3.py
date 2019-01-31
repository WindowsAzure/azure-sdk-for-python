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


class DataConnectorDataTypeCommon(Model):
    """Common field for data type in data connectors.

    :param state: Describe whther this data type connection is enabled or not.
     Possible values include: 'Enabled', 'Disabled'
    :type state: str or ~azure.mgmt.securityinsight.models.DataTypeState
    """

    _attribute_map = {
        'state': {'key': 'state', 'type': 'str'},
    }

    def __init__(self, *, state=None, **kwargs) -> None:
        super(DataConnectorDataTypeCommon, self).__init__(**kwargs)
        self.state = state
