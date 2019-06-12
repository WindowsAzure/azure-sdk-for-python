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

from .tracked_resource import TrackedResource


class Assignment(TrackedResource):
    """Represents a blueprint assignment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: String Id used to locate any resource on Azure.
    :vartype id: str
    :ivar type: Type of this resource.
    :vartype type: str
    :ivar name: Name of this resource.
    :vartype name: str
    :param location: Required. The location of this blueprint assignment.
    :type location: str
    :param identity: Required. Managed identity for this blueprint assignment.
    :type identity: ~azure.mgmt.blueprint.models.ManagedServiceIdentity
    :param display_name: One-liner string explain this resource.
    :type display_name: str
    :param description: Multi-line explain this resource.
    :type description: str
    :param blueprint_id: ID of the published version of a blueprint
     definition.
    :type blueprint_id: str
    :param parameters: Required. Blueprint assignment parameter values.
    :type parameters: dict[str,
     ~azure.mgmt.blueprint.models.ParameterValueBase]
    :param resource_groups: Required. Names and locations of resource group
     placeholders.
    :type resource_groups: dict[str,
     ~azure.mgmt.blueprint.models.ResourceGroupValue]
    :ivar status: Status of blueprint assignment. This field is readonly.
    :vartype status: ~azure.mgmt.blueprint.models.AssignmentStatus
    :param locks: Defines how resources deployed by a blueprint assignment are
     locked.
    :type locks: ~azure.mgmt.blueprint.models.AssignmentLockSettings
    :ivar provisioning_state: State of the blueprint assignment. Possible
     values include: 'creating', 'validating', 'waiting', 'deploying',
     'cancelling', 'locking', 'succeeded', 'failed', 'canceled', 'deleting'
    :vartype provisioning_state: str or
     ~azure.mgmt.blueprint.models.AssignmentProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'location': {'required': True},
        'identity': {'required': True},
        'display_name': {'max_length': 256},
        'description': {'max_length': 500},
        'parameters': {'required': True},
        'resource_groups': {'required': True},
        'status': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'identity': {'key': 'identity', 'type': 'ManagedServiceIdentity'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'blueprint_id': {'key': 'properties.blueprintId', 'type': 'str'},
        'parameters': {'key': 'properties.parameters', 'type': '{ParameterValueBase}'},
        'resource_groups': {'key': 'properties.resourceGroups', 'type': '{ResourceGroupValue}'},
        'status': {'key': 'properties.status', 'type': 'AssignmentStatus'},
        'locks': {'key': 'properties.locks', 'type': 'AssignmentLockSettings'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(Assignment, self).__init__(**kwargs)
        self.identity = kwargs.get('identity', None)
        self.display_name = kwargs.get('display_name', None)
        self.description = kwargs.get('description', None)
        self.blueprint_id = kwargs.get('blueprint_id', None)
        self.parameters = kwargs.get('parameters', None)
        self.resource_groups = kwargs.get('resource_groups', None)
        self.status = None
        self.locks = kwargs.get('locks', None)
        self.provisioning_state = None
