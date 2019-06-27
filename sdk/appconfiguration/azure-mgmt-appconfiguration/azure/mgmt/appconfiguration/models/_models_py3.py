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


class ApiKey(Model):
    """An API key used for authenticating with a configuration store endpoint.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The key ID.
    :vartype id: str
    :ivar name: A name for the key describing its usage.
    :vartype name: str
    :ivar value: The value of the key that is used for authentication
     purposes.
    :vartype value: str
    :ivar connection_string: A connection string that can be used by
     supporting clients for authentication.
    :vartype connection_string: str
    :ivar last_modified: The last time any of the key's properties were
     modified.
    :vartype last_modified: datetime
    :ivar read_only: Whether this key can only be used for read operations.
    :vartype read_only: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'value': {'readonly': True},
        'connection_string': {'readonly': True},
        'last_modified': {'readonly': True},
        'read_only': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
        'connection_string': {'key': 'connectionString', 'type': 'str'},
        'last_modified': {'key': 'lastModified', 'type': 'iso-8601'},
        'read_only': {'key': 'readOnly', 'type': 'bool'},
    }

    def __init__(self, **kwargs) -> None:
        super(ApiKey, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.value = None
        self.connection_string = None
        self.last_modified = None
        self.read_only = None


class CheckNameAvailabilityParameters(Model):
    """Parameters used for checking whether a resource name is available.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name to check for availability.
    :type name: str
    :ivar type: Required. The resource type to check for name availability.
     Default value: "Microsoft.AppConfiguration/configurationStores" .
    :vartype type: str
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True, 'constant': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    type = "Microsoft.AppConfiguration/configurationStores"

    def __init__(self, *, name: str, **kwargs) -> None:
        super(CheckNameAvailabilityParameters, self).__init__(**kwargs)
        self.name = name


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class Resource(Model):
    """An Azure resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param location: Required. The location of the resource. This cannot be
     changed after the resource is created.
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
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
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, location: str, tags=None, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.location = location
        self.tags = tags


class ConfigurationStore(Resource):
    """The configuration store along with all resource properties. The
    Configuration Store will have all information to begin utilizing it.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param location: Required. The location of the resource. This cannot be
     changed after the resource is created.
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :ivar provisioning_state: The provisioning state of the configuration
     store. Possible values include: 'Creating', 'Updating', 'Deleting',
     'Succeeded', 'Failed', 'Canceled'
    :vartype provisioning_state: str or
     ~azure.mgmt.appconfiguration.models.ProvisioningState
    :ivar creation_date: The creation date of configuration store.
    :vartype creation_date: datetime
    :ivar endpoint: The DNS endpoint where the configuration store API will be
     available.
    :vartype endpoint: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'provisioning_state': {'readonly': True},
        'creation_date': {'readonly': True},
        'endpoint': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'creation_date': {'key': 'properties.creationDate', 'type': 'iso-8601'},
        'endpoint': {'key': 'properties.endpoint', 'type': 'str'},
    }

    def __init__(self, *, location: str, tags=None, **kwargs) -> None:
        super(ConfigurationStore, self).__init__(location=location, tags=tags, **kwargs)
        self.provisioning_state = None
        self.creation_date = None
        self.endpoint = None


class ConfigurationStoreUpdateParameters(Model):
    """The parameters for updating a configuration store.

    :param properties: The properties for updating a configuration store.
    :type properties: object
    :param tags: The ARM resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'properties': {'key': 'properties', 'type': 'object'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, properties=None, tags=None, **kwargs) -> None:
        super(ConfigurationStoreUpdateParameters, self).__init__(**kwargs)
        self.properties = properties
        self.tags = tags


class Error(Model):
    """AppConfiguration error object.

    :param code: Error code.
    :type code: str
    :param message: Error message.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, message: str=None, **kwargs) -> None:
        super(Error, self).__init__(**kwargs)
        self.code = code
        self.message = message


class ErrorException(HttpOperationError):
    """Server responsed with exception of type: 'Error'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorException, self).__init__(deserialize, response, 'Error', *args)


class NameAvailabilityStatus(Model):
    """The result of a request to check the availability of a resource name.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name_available: The value indicating whether the resource name is
     available.
    :vartype name_available: bool
    :ivar message: If any, the error message that provides more detail for the
     reason that the name is not available.
    :vartype message: str
    :ivar reason: If any, the reason that the name is not available.
    :vartype reason: str
    """

    _validation = {
        'name_available': {'readonly': True},
        'message': {'readonly': True},
        'reason': {'readonly': True},
    }

    _attribute_map = {
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'message': {'key': 'message', 'type': 'str'},
        'reason': {'key': 'reason', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(NameAvailabilityStatus, self).__init__(**kwargs)
        self.name_available = None
        self.message = None
        self.reason = None


class OperationDefinition(Model):
    """The definition of a configuration store operation.

    :param name: Operation name: {provider}/{resource}/{operation}.
    :type name: str
    :param display: The display information for the configuration store
     operation.
    :type display:
     ~azure.mgmt.appconfiguration.models.OperationDefinitionDisplay
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDefinitionDisplay'},
    }

    def __init__(self, *, name: str=None, display=None, **kwargs) -> None:
        super(OperationDefinition, self).__init__(**kwargs)
        self.name = name
        self.display = display


class OperationDefinitionDisplay(Model):
    """The display information for a configuration store operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provider: The resource provider name: Microsoft App Configuration."
    :vartype provider: str
    :param resource: The resource on which the operation is performed.
    :type resource: str
    :param operation: The operation that users can perform.
    :type operation: str
    :param description: The description for the operation.
    :type description: str
    """

    _validation = {
        'provider': {'readonly': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, *, resource: str=None, operation: str=None, description: str=None, **kwargs) -> None:
        super(OperationDefinitionDisplay, self).__init__(**kwargs)
        self.provider = None
        self.resource = resource
        self.operation = operation
        self.description = description


class RegenerateKeyParameters(Model):
    """The parameters used to regenerate an API key.

    :param id: The id of the key to regenerate.
    :type id: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, **kwargs) -> None:
        super(RegenerateKeyParameters, self).__init__(**kwargs)
        self.id = id
