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


class DataConnector(Model):
    """Data connector.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: OfficeDataConnector, TIDataConnector,
    AwsCloudTrailDataConnector, AADDataConnector, ASCDataConnector,
    MCASDataConnector, AATPDataConnector, MDATPDataConnector

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar type: Azure resource type
    :vartype type: str
    :ivar name: Azure resource name
    :vartype name: str
    :param etag: Etag of the data connector.
    :type etag: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'kind': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'Office365': 'OfficeDataConnector', 'ThreatIntelligence': 'TIDataConnector', 'AmazonWebServicesCloudTrail': 'AwsCloudTrailDataConnector', 'AzureActiveDirectory': 'AADDataConnector', 'AzureSecurityCenter': 'ASCDataConnector', 'MicrosoftCloudAppSecurity': 'MCASDataConnector', 'AzureAdvancedThreatProtection': 'AATPDataConnector', 'MicrosoftDefenderAdvancedThreatProtection': 'MDATPDataConnector'}
    }

    def __init__(self, *, etag: str=None, **kwargs) -> None:
        super(DataConnector, self).__init__(**kwargs)
        self.id = None
        self.type = None
        self.name = None
        self.etag = etag
        self.kind = None
