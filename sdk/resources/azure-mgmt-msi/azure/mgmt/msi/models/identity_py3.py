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


class Identity(Model):
    """Describes an identity resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The id of the created identity.
    :vartype id: str
    :ivar name: The name of the created identity.
    :vartype name: str
    :param location: The Azure region where the identity lives.
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :ivar tenant_id: The id of the tenant which the identity belongs to.
    :vartype tenant_id: str
    :ivar principal_id: The id of the service principal object associated with
     the created identity.
    :vartype principal_id: str
    :ivar client_id: The id of the app associated with the identity. This is a
     random generated UUID by MSI.
    :vartype client_id: str
    :ivar client_secret_url:  The ManagedServiceIdentity DataPlane URL that
     can be queried to obtain the identity credentials. If identity is user
     assigned, then the clientSecretUrl will not be present in the response,
     otherwise it will be present.
    :vartype client_secret_url: str
    :ivar type: The type of resource i.e.
     Microsoft.ManagedIdentity/userAssignedIdentities. Possible values include:
     'Microsoft.ManagedIdentity/userAssignedIdentities'
    :vartype type: str or ~azure.mgmt.msi.models.UserAssignedIdentities
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'tenant_id': {'readonly': True},
        'principal_id': {'readonly': True},
        'client_id': {'readonly': True},
        'client_secret_url': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'tenant_id': {'key': 'properties.tenantId', 'type': 'str'},
        'principal_id': {'key': 'properties.principalId', 'type': 'str'},
        'client_id': {'key': 'properties.clientId', 'type': 'str'},
        'client_secret_url': {'key': 'properties.clientSecretUrl', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, tags=None, **kwargs) -> None:
        super(Identity, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.location = location
        self.tags = tags
        self.tenant_id = None
        self.principal_id = None
        self.client_id = None
        self.client_secret_url = None
        self.type = None
