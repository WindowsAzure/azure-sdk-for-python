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
from msrest.exceptions import HttpOperationError


class AccountKeyRegenerateRequest(Model):
    """Request for account key regeneration.

    :param serial: serial of key to be regenerated. Default value: 1 .
    :type serial: int
    """

    _attribute_map = {
        'serial': {'key': 'serial', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(AccountKeyRegenerateRequest, self).__init__(**kwargs)
        self.serial = kwargs.get('serial', 1)


class AccountKeys(Model):
    """Developer Keys of account.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar primary_key: value of primary key.
    :vartype primary_key: str
    :ivar secondary_key: value of secondary key.
    :vartype secondary_key: str
    """

    _validation = {
        'primary_key': {'readonly': True},
        'secondary_key': {'readonly': True},
    }

    _attribute_map = {
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AccountKeys, self).__init__(**kwargs)
        self.primary_key = None
        self.secondary_key = None


class Resource(Model):
    """Resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class AzureEntityResource(Resource):
    """The resource model definition for a Azure Resource Manager resource with an
    etag.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :ivar etag: Resource Etag.
    :vartype etag: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AzureEntityResource, self).__init__(**kwargs)
        self.etag = None


class CheckNameAvailabilityRequest(Model):
    """Check Name Availability Request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Resource Name To Verify
    :type name: str
    :param type: Required. Fully qualified resource type which includes
     provider namespace
    :type type: str
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(CheckNameAvailabilityRequest, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.type = kwargs.get('type', None)


class CheckNameAvailabilityResponse(Model):
    """Check Name Availability Response.

    All required parameters must be populated in order to send to Azure.

    :param name_available: Required. if name Available. Possible values
     include: 'true', 'false'
    :type name_available: str or
     ~azure.mgmt.mixedreality.models.NameAvailability
    :param reason: Resource Name To Verify. Possible values include:
     'Invalid', 'AlreadyExists'
    :type reason: str or ~azure.mgmt.mixedreality.models.NameUnavailableReason
    :param message: detail message
    :type message: str
    """

    _validation = {
        'name_available': {'required': True},
    }

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'str'},
        'reason': {'key': 'reason', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(CheckNameAvailabilityResponse, self).__init__(**kwargs)
        self.name_available = kwargs.get('name_available', None)
        self.reason = kwargs.get('reason', None)
        self.message = kwargs.get('message', None)


class CloudError(Model):
    """An Error response.

    :param error:
    :type error: ~azure.mgmt.mixedreality.models.CloudErrorBody
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'CloudErrorBody'},
    }

    def __init__(self, **kwargs):
        super(CloudError, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)


class CloudErrorException(HttpOperationError):
    """Server responsed with exception of type: 'CloudError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(CloudErrorException, self).__init__(deserialize, response, 'CloudError', *args)


class CloudErrorBody(Model):
    """An error response from Azure.

    :param code: An identifier for the error. Codes are invariant and are
     intended to be consumed programmatically.
    :type code: str
    :param message: A message describing the error, intended to be suitable
     for displaying in a user interface.
    :type message: str
    :param target: The target of the particular error. For example, the name
     of the property in error.
    :type target: str
    :param details: A list of additional details about the error.
    :type details: list[~azure.mgmt.mixedreality.models.CloudErrorBody]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[CloudErrorBody]'},
    }

    def __init__(self, **kwargs):
        super(CloudErrorBody, self).__init__(**kwargs)
        self.code = kwargs.get('code', None)
        self.message = kwargs.get('message', None)
        self.target = kwargs.get('target', None)
        self.details = kwargs.get('details', None)


class Operation(Model):
    """REST API operation.

    :param name: Operation name: {provider}/{resource}/{operation}
    :type name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.mixedreality.models.OperationDisplay
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(self, **kwargs):
        super(Operation, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display = kwargs.get('display', None)


class OperationDisplay(Model):
    """The object that represents the operation.

    All required parameters must be populated in order to send to Azure.

    :param provider: Required. Service provider: Microsoft.ResourceProvider
    :type provider: str
    :param resource: Required. Resource on which the operation is performed:
     Profile, endpoint, etc.
    :type resource: str
    :param operation: Required. Operation type: Read, write, delete, etc.
    :type operation: str
    :param description: Required. Description of operation
    :type description: str
    """

    _validation = {
        'provider': {'required': True},
        'resource': {'required': True},
        'operation': {'required': True},
        'description': {'required': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)
        self.operation = kwargs.get('operation', None)
        self.description = kwargs.get('description', None)


class ProxyResource(Resource):
    """The resource model definition for a ARM proxy resource. It will have
    everything other than required location and tags.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ProxyResource, self).__init__(**kwargs)


class TrackedResource(Resource):
    """The resource model definition for a ARM tracked top level resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives
    :type location: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(TrackedResource, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.location = kwargs.get('location', None)


class SpatialAnchorsAccount(TrackedResource):
    """SpatialAnchorsAccount Response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource Id for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The type of the resource. Ex-
     Microsoft.Compute/virtualMachines or Microsoft.Storage/storageAccounts.
    :vartype type: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives
    :type location: str
    :ivar account_id: unique id of certain account.
    :vartype account_id: str
    :ivar account_domain: Correspond domain name of certain Spatial Anchors
     Account
    :vartype account_domain: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'account_id': {'readonly': True},
        'account_domain': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'account_id': {'key': 'properties.accountId', 'type': 'str'},
        'account_domain': {'key': 'properties.accountDomain', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SpatialAnchorsAccount, self).__init__(**kwargs)
        self.account_id = None
        self.account_domain = None
