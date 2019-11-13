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


class ModelsSummary(Model):
    """Summary of all trained custom models.

    All required parameters must be populated in order to send to Azure.

    :param count: Required. Current count of trained custom models.
    :type count: int
    :param limit: Required. Max number of models that can be trained for this
     subscription.
    :type limit: int
    :param last_updated_date_time: Required. Date and time (UTC) when the
     summary was last updated.
    :type last_updated_date_time: datetime
    """

    _validation = {
        'count': {'required': True},
        'limit': {'required': True},
        'last_updated_date_time': {'required': True},
    }

    _attribute_map = {
        'count': {'key': 'count', 'type': 'int'},
        'limit': {'key': 'limit', 'type': 'int'},
        'last_updated_date_time': {'key': 'lastUpdatedDateTime', 'type': 'iso-8601'},
    }

    def __init__(self, *, count: int, limit: int, last_updated_date_time, **kwargs) -> None:
        super(ModelsSummary, self).__init__(**kwargs)
        self.count = count
        self.limit = limit
        self.last_updated_date_time = last_updated_date_time
