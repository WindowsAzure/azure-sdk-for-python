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


class Source(Model):
    """Specifies the log search query.

    All required parameters must be populated in order to send to Azure.

    :param query: Log search query. Required for action type - AlertingAction
    :type query: str
    :param authorized_resources: List of  Resource referred into query
    :type authorized_resources: list[str]
    :param data_source_id: Required. The resource uri over which log search
     query is to be run.
    :type data_source_id: str
    :param query_type: Set value to 'ResultCount'. Possible values include:
     'ResultCount'
    :type query_type: str or ~azure.mgmt.monitor.models.QueryType
    """

    _validation = {
        'data_source_id': {'required': True},
    }

    _attribute_map = {
        'query': {'key': 'query', 'type': 'str'},
        'authorized_resources': {'key': 'authorizedResources', 'type': '[str]'},
        'data_source_id': {'key': 'dataSourceId', 'type': 'str'},
        'query_type': {'key': 'queryType', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Source, self).__init__(**kwargs)
        self.query = kwargs.get('query', None)
        self.authorized_resources = kwargs.get('authorized_resources', None)
        self.data_source_id = kwargs.get('data_source_id', None)
        self.query_type = kwargs.get('query_type', None)
