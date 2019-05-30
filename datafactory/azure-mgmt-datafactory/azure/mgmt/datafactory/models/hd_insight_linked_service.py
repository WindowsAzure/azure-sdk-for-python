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

from .linked_service import LinkedService


class HDInsightLinkedService(LinkedService):
    """HDInsight linked service.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param connect_via: The integration runtime reference.
    :type connect_via:
     ~azure.mgmt.datafactory.models.IntegrationRuntimeReference
    :param description: Linked service description.
    :type description: str
    :param parameters: Parameters for linked service.
    :type parameters: dict[str,
     ~azure.mgmt.datafactory.models.ParameterSpecification]
    :param annotations: List of tags that can be used for describing the
     linked service.
    :type annotations: list[object]
    :param type: Required. Constant filled by server.
    :type type: str
    :param cluster_uri: Required. HDInsight cluster URI. Type: string (or
     Expression with resultType string).
    :type cluster_uri: object
    :param user_name: HDInsight cluster user name. Type: string (or Expression
     with resultType string).
    :type user_name: object
    :param password: HDInsight cluster password.
    :type password: ~azure.mgmt.datafactory.models.SecretBase
    :param linked_service_name: The Azure Storage linked service reference.
    :type linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param hcatalog_linked_service_name: A reference to the Azure SQL linked
     service that points to the HCatalog database.
    :type hcatalog_linked_service_name:
     ~azure.mgmt.datafactory.models.LinkedServiceReference
    :param encrypted_credential: The encrypted credential used for
     authentication. Credentials are encrypted using the integration runtime
     credential manager. Type: string (or Expression with resultType string).
    :type encrypted_credential: object
    :param is_esp_enabled: Specify if the HDInsight is created with ESP
     (Enterprise Security Package). Type: Boolean.
    :type is_esp_enabled: object
    """

    _validation = {
        'type': {'required': True},
        'cluster_uri': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'cluster_uri': {'key': 'typeProperties.clusterUri', 'type': 'object'},
        'user_name': {'key': 'typeProperties.userName', 'type': 'object'},
        'password': {'key': 'typeProperties.password', 'type': 'SecretBase'},
        'linked_service_name': {'key': 'typeProperties.linkedServiceName', 'type': 'LinkedServiceReference'},
        'hcatalog_linked_service_name': {'key': 'typeProperties.hcatalogLinkedServiceName', 'type': 'LinkedServiceReference'},
        'encrypted_credential': {'key': 'typeProperties.encryptedCredential', 'type': 'object'},
        'is_esp_enabled': {'key': 'typeProperties.isEspEnabled', 'type': 'object'},
    }

    def __init__(self, **kwargs):
        super(HDInsightLinkedService, self).__init__(**kwargs)
        self.cluster_uri = kwargs.get('cluster_uri', None)
        self.user_name = kwargs.get('user_name', None)
        self.password = kwargs.get('password', None)
        self.linked_service_name = kwargs.get('linked_service_name', None)
        self.hcatalog_linked_service_name = kwargs.get('hcatalog_linked_service_name', None)
        self.encrypted_credential = kwargs.get('encrypted_credential', None)
        self.is_esp_enabled = kwargs.get('is_esp_enabled', None)
        self.type = 'HDInsight'
