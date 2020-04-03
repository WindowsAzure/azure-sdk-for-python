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


class Resource(Model):
    """Definition of a Resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified identifier of the resource
    :vartype id: str
    :ivar name: Name of the resource
    :vartype name: str
    :ivar type: Type of the resource
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

    def __init__(self, **kwargs) -> None:
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class ApplyUpdate(Resource):
    """Apply Update request.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified identifier of the resource
    :vartype id: str
    :ivar name: Name of the resource
    :vartype name: str
    :ivar type: Type of the resource
    :vartype type: str
    :param status: The status. Possible values include: 'Pending',
     'InProgress', 'Completed', 'RetryNow', 'RetryLater'
    :type status: str or ~azure.mgmt.maintenance.models.UpdateStatus
    :param resource_id: The resourceId
    :type resource_id: str
    :param last_update_time: Last Update time
    :type last_update_time: datetime
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
        'status': {'key': 'properties.status', 'type': 'str'},
        'resource_id': {'key': 'properties.resourceId', 'type': 'str'},
        'last_update_time': {'key': 'properties.lastUpdateTime', 'type': 'iso-8601'},
    }

    def __init__(self, *, status=None, resource_id: str=None, last_update_time=None, **kwargs) -> None:
        super(ApplyUpdate, self).__init__(**kwargs)
        self.status = status
        self.resource_id = resource_id
        self.last_update_time = last_update_time


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class ConfigurationAssignment(Resource):
    """Configuration Assignment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified identifier of the resource
    :vartype id: str
    :ivar name: Name of the resource
    :vartype name: str
    :ivar type: Type of the resource
    :vartype type: str
    :param location: Location of the resource
    :type location: str
    :param maintenance_configuration_id: The maintenance configuration Id
    :type maintenance_configuration_id: str
    :param resource_id: The unique resourceId
    :type resource_id: str
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
        'location': {'key': 'location', 'type': 'str'},
        'maintenance_configuration_id': {'key': 'properties.maintenanceConfigurationId', 'type': 'str'},
        'resource_id': {'key': 'properties.resourceId', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, maintenance_configuration_id: str=None, resource_id: str=None, **kwargs) -> None:
        super(ConfigurationAssignment, self).__init__(**kwargs)
        self.location = location
        self.maintenance_configuration_id = maintenance_configuration_id
        self.resource_id = resource_id


class ErrorDetails(Model):
    """An error response details received from the Azure Maintenance service.

    :param code: Service-defined error code. This code serves as a sub-status
     for the HTTP error code specified in the response.
    :type code: str
    :param message: Human-readable representation of the error.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, message: str=None, **kwargs) -> None:
        super(ErrorDetails, self).__init__(**kwargs)
        self.code = code
        self.message = message


class MaintenanceConfiguration(Resource):
    """Maintenance configuration record type.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Fully qualified identifier of the resource
    :vartype id: str
    :ivar name: Name of the resource
    :vartype name: str
    :ivar type: Type of the resource
    :vartype type: str
    :param location: Gets or sets location of the resource
    :type location: str
    :param tags: Gets or sets tags of the resource
    :type tags: dict[str, str]
    :param namespace: Gets or sets namespace of the resource e.g.
     Microsoft.Maintenance or Microsoft.Sql
    :type namespace: str
    :param extension_properties: Gets or sets extensionProperties of the
     maintenanceConfiguration. This is for future use only and would be a set
     of key value pairs for additional information e.g. whether to follow SDP
     etc.
    :type extension_properties: dict[str, str]
    :param maintenance_scope: Gets or sets maintenanceScope of the
     configuration. It represent the impact area of the maintenance. Possible
     values include: 'All', 'Host', 'Resource', 'InResource'
    :type maintenance_scope: str or
     ~azure.mgmt.maintenance.models.MaintenanceScope
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
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'namespace': {'key': 'properties.namespace', 'type': 'str'},
        'extension_properties': {'key': 'properties.extensionProperties', 'type': '{str}'},
        'maintenance_scope': {'key': 'properties.maintenanceScope', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, tags=None, namespace: str=None, extension_properties=None, maintenance_scope=None, **kwargs) -> None:
        super(MaintenanceConfiguration, self).__init__(**kwargs)
        self.location = location
        self.tags = tags
        self.namespace = namespace
        self.extension_properties = extension_properties
        self.maintenance_scope = maintenance_scope


class MaintenanceError(Model):
    """An error response received from the Azure Maintenance service.

    :param error: Details of the error
    :type error: ~azure.mgmt.maintenance.models.ErrorDetails
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorDetails'},
    }

    def __init__(self, *, error=None, **kwargs) -> None:
        super(MaintenanceError, self).__init__(**kwargs)
        self.error = error


class MaintenanceErrorException(HttpOperationError):
    """Server responsed with exception of type: 'MaintenanceError'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(MaintenanceErrorException, self).__init__(deserialize, response, 'MaintenanceError', *args)


class Operation(Model):
    """Represents an operation returned by the GetOperations request.

    :param name: Name of the operation
    :type name: str
    :param display: Display name of the operation
    :type display: ~azure.mgmt.maintenance.models.OperationInfo
    :param origin: Origin of the operation
    :type origin: str
    :param properties: Properties of the operation
    :type properties: object
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationInfo'},
        'origin': {'key': 'origin', 'type': 'str'},
        'properties': {'key': 'properties', 'type': 'object'},
    }

    def __init__(self, *, name: str=None, display=None, origin: str=None, properties=None, **kwargs) -> None:
        super(Operation, self).__init__(**kwargs)
        self.name = name
        self.display = display
        self.origin = origin
        self.properties = properties


class OperationInfo(Model):
    """Information about an operation.

    :param provider: Name of the provider
    :type provider: str
    :param resource: Name of the resource type
    :type resource: str
    :param operation: Name of the operation
    :type operation: str
    :param description: Description of the operation
    :type description: str
    """

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(self, *, provider: str=None, resource: str=None, operation: str=None, description: str=None, **kwargs) -> None:
        super(OperationInfo, self).__init__(**kwargs)
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description


class Update(Model):
    """Maintenance update on a resource.

    :param maintenance_scope: The impact area. Possible values include: 'All',
     'Host', 'Resource', 'InResource'
    :type maintenance_scope: str or
     ~azure.mgmt.maintenance.models.MaintenanceScope
    :param impact_type: The impact type. Possible values include: 'None',
     'Freeze', 'Restart', 'Redeploy'
    :type impact_type: str or ~azure.mgmt.maintenance.models.ImpactType
    :param status: The status. Possible values include: 'Pending',
     'InProgress', 'Completed', 'RetryNow', 'RetryLater'
    :type status: str or ~azure.mgmt.maintenance.models.UpdateStatus
    :param impact_duration_in_sec: Duration of impact in seconds
    :type impact_duration_in_sec: int
    :param not_before: Time when Azure will start force updates if not
     self-updated by customer before this time
    :type not_before: datetime
    :param resource_id: The resourceId
    :type resource_id: str
    """

    _attribute_map = {
        'maintenance_scope': {'key': 'maintenanceScope', 'type': 'str'},
        'impact_type': {'key': 'impactType', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'impact_duration_in_sec': {'key': 'impactDurationInSec', 'type': 'int'},
        'not_before': {'key': 'notBefore', 'type': 'iso-8601'},
        'resource_id': {'key': 'properties.resourceId', 'type': 'str'},
    }

    def __init__(self, *, maintenance_scope=None, impact_type=None, status=None, impact_duration_in_sec: int=None, not_before=None, resource_id: str=None, **kwargs) -> None:
        super(Update, self).__init__(**kwargs)
        self.maintenance_scope = maintenance_scope
        self.impact_type = impact_type
        self.status = status
        self.impact_duration_in_sec = impact_duration_in_sec
        self.not_before = not_before
        self.resource_id = resource_id
