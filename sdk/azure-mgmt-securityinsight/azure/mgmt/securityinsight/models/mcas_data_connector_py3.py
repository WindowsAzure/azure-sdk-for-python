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

from .data_connector_py3 import DataConnector


class MCASDataConnector(DataConnector):
    """Represents MCAS (Microsoft Cloud App Security) data connector.

    All required parameters must be populated in order to send to Azure.

    :param etag: Etag of the azure resource
    :type etag: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param tenant_id: The tenant id to connect to, and get the data from.
    :type tenant_id: str
    :param data_types: The available data types for the connector.
    :type data_types:
     ~azure.mgmt.securityinsight.models.MCASDataConnectorDataTypes
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'tenant_id': {'key': 'properties.tenantId', 'type': 'str'},
        'data_types': {'key': 'properties.dataTypes', 'type': 'MCASDataConnectorDataTypes'},
    }

    def __init__(self, *, etag: str=None, tenant_id: str=None, data_types=None, **kwargs) -> None:
        super(MCASDataConnector, self).__init__(etag=etag, **kwargs)
        self.tenant_id = tenant_id
        self.data_types = data_types
        self.kind = 'MicrosoftCloudAppSecurity'
