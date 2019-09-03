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

from .data_connector import DataConnector


class AATPDataConnector(DataConnector):
    """Represents AATP (Azure Advanced Threat Protection) data connector.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param etag: Etag of the data connector.
    :type etag: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param tenant_id: The tenant id to connect to, and get the data from.
    :type tenant_id: str
    :param data_types: The available data types for the connector.
    :type data_types:
     ~azure.mgmt.securityinsight.models.AlertsDataTypeOfDataConnector
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'kind': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'tenant_id': {'key': 'properties.tenantId', 'type': 'str'},
        'data_types': {'key': 'properties.dataTypes', 'type': 'AlertsDataTypeOfDataConnector'},
    }

    def __init__(self, **kwargs):
        super(AATPDataConnector, self).__init__(**kwargs)
        self.tenant_id = kwargs.get('tenant_id', None)
        self.data_types = kwargs.get('data_types', None)
        self.kind = 'AzureAdvancedThreatProtection'
