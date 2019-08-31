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

from .linked_service_py3 import LinkedService


class AzureKeyVaultLinkedService(LinkedService):
    """Azure Key Vault linked service.

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
    :param base_url: Required. The base URL of the Azure Key Vault. e.g.
     https://myakv.vault.azure.net Type: string (or Expression with resultType
     string).
    :type base_url: object
    """

    _validation = {
        'type': {'required': True},
        'base_url': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
        'base_url': {'key': 'typeProperties.baseUrl', 'type': 'object'},
    }

    def __init__(self, *, base_url, additional_properties=None, connect_via=None, description: str=None, parameters=None, annotations=None, **kwargs) -> None:
        super(AzureKeyVaultLinkedService, self).__init__(additional_properties=additional_properties, connect_via=connect_via, description=description, parameters=parameters, annotations=annotations, **kwargs)
        self.base_url = base_url
        self.type = 'AzureKeyVault'
