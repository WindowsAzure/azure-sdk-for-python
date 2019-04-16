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


class UploadCertificateResponse(Model):
    """The upload registration certificate response.

    All required parameters must be populated in order to send to Azure.

    :param auth_type: Specifies authentication type. Possible values include:
     'Invalid', 'AzureActiveDirectory'
    :type auth_type: str or ~azure.mgmt.edgegateway.models.AuthenticationType
    :param resource_id: Required. The resource ID of the Data Box Edge/Gateway
     device.
    :type resource_id: str
    :param aad_authority: Required. Azure Active Directory tenant authority.
    :type aad_authority: str
    :param aad_tenant_id: Required. Azure Active Directory tenant ID.
    :type aad_tenant_id: str
    :param service_principal_client_id: Required. Azure Active Directory
     service principal client ID.
    :type service_principal_client_id: str
    :param service_principal_object_id: Required. Azure Active Directory
     service principal object ID.
    :type service_principal_object_id: str
    :param azure_management_endpoint_audience: Required. The azure management
     endpoint audience.
    :type azure_management_endpoint_audience: str
    """

    _validation = {
        'resource_id': {'required': True},
        'aad_authority': {'required': True},
        'aad_tenant_id': {'required': True},
        'service_principal_client_id': {'required': True},
        'service_principal_object_id': {'required': True},
        'azure_management_endpoint_audience': {'required': True},
    }

    _attribute_map = {
        'auth_type': {'key': 'authType', 'type': 'str'},
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'aad_authority': {'key': 'aadAuthority', 'type': 'str'},
        'aad_tenant_id': {'key': 'aadTenantId', 'type': 'str'},
        'service_principal_client_id': {'key': 'servicePrincipalClientId', 'type': 'str'},
        'service_principal_object_id': {'key': 'servicePrincipalObjectId', 'type': 'str'},
        'azure_management_endpoint_audience': {'key': 'azureManagementEndpointAudience', 'type': 'str'},
    }

    def __init__(self, *, resource_id: str, aad_authority: str, aad_tenant_id: str, service_principal_client_id: str, service_principal_object_id: str, azure_management_endpoint_audience: str, auth_type=None, **kwargs) -> None:
        super(UploadCertificateResponse, self).__init__(**kwargs)
        self.auth_type = auth_type
        self.resource_id = resource_id
        self.aad_authority = aad_authority
        self.aad_tenant_id = aad_tenant_id
        self.service_principal_client_id = service_principal_client_id
        self.service_principal_object_id = service_principal_object_id
        self.azure_management_endpoint_audience = azure_management_endpoint_audience
