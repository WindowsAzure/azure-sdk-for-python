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


class AwsCloudTrailDataConnector(DataConnector):
    """Represents Amazon Web Services CloudTrail data connector.

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
    :param aws_role_arn: The Aws Role Arn (with CloudTrailReadOnly policy)
     that is used to access the Aws account.
    :type aws_role_arn: str
    :param data_types: The available data types for the connector.
    :type data_types:
     ~azure.mgmt.securityinsight.models.AwsCloudTrailDataConnectorDataTypes
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
        'aws_role_arn': {'key': 'properties.awsRoleArn', 'type': 'str'},
        'data_types': {'key': 'properties.dataTypes', 'type': 'AwsCloudTrailDataConnectorDataTypes'},
    }

    def __init__(self, **kwargs):
        super(AwsCloudTrailDataConnector, self).__init__(**kwargs)
        self.aws_role_arn = kwargs.get('aws_role_arn', None)
        self.data_types = kwargs.get('data_types', None)
        self.kind = 'AmazonWebServicesCloudTrail'
