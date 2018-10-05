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

from .proxy_resource import ProxyResource


class Component(ProxyResource):
    """Model for component.

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
    :ivar etag: For optimistic concurrency control.
    :vartype etag: str
    :ivar workspace_id: ID of the workspace.
    :vartype workspace_id: str
    :ivar solution_id: ID of the OMS solution this component belong to.
    :vartype solution_id: str
    :ivar workload_type: Type of the workload. Possible values include:
     'BaseOS', 'SQL', 'IIS', 'Apache'
    :vartype workload_type: str or
     ~azure.mgmt.workloadmonitor.models.WorkloadType
    :ivar component_name: Name of the component.
    :vartype component_name: str
    :ivar component_type_id: ID of the component type.
    :vartype component_type_id: str
    :ivar component_type_name: Name of the component type. Qualifies the type
     of component such as whether it is a SQL database, logical disk, website,
     etc.
    :vartype component_type_name: str
    :ivar component_type_group_category: Component type group category.
     Classification of component type groups into a logical category. e.g.
     Network, Disk, Memory, CPU.
    :vartype component_type_group_category: str
    :ivar health_state: Health state of the component. Possible values
     include: 'Error', 'Warning', 'Success', 'Unknown', 'Uninitialized'
    :vartype health_state: str or
     ~azure.mgmt.workloadmonitor.models.HealthState
    :ivar health_state_category: Category of component's health state.
     Possible values include: 'Identity', 'CustomGroup'
    :vartype health_state_category: str or
     ~azure.mgmt.workloadmonitor.models.HealthStateCategory
    :ivar health_state_changes_start_time: Start time for health state
     changes.
    :vartype health_state_changes_start_time: datetime
    :ivar health_state_changes_end_time: End time for health state changes.
    :vartype health_state_changes_end_time: datetime
    :ivar last_health_state_change_time: Time of last health state change.
    :vartype last_health_state_change_time: datetime
    :ivar vm_id: ID of the VM this component belongs to.
    :vartype vm_id: str
    :ivar vm_name: Name of the VM this component belongs to.
    :vartype vm_name: str
    :ivar vm_tags: Tags on the VM this component belongs to.
    :vartype vm_tags: dict[str, str]
    :ivar aggregate_properties: Properties requested in aggregation queries.
    :vartype aggregate_properties: dict[str, str]
    :ivar children: component children.
    :vartype children: list[~azure.mgmt.workloadmonitor.models.Component]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
        'workspace_id': {'readonly': True},
        'solution_id': {'readonly': True},
        'workload_type': {'readonly': True},
        'component_name': {'readonly': True},
        'component_type_id': {'readonly': True},
        'component_type_name': {'readonly': True},
        'component_type_group_category': {'readonly': True},
        'health_state': {'readonly': True},
        'health_state_category': {'readonly': True},
        'health_state_changes_start_time': {'readonly': True},
        'health_state_changes_end_time': {'readonly': True},
        'last_health_state_change_time': {'readonly': True},
        'vm_id': {'readonly': True},
        'vm_name': {'readonly': True},
        'vm_tags': {'readonly': True},
        'aggregate_properties': {'readonly': True},
        'children': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'workspace_id': {'key': 'properties.workspaceId', 'type': 'str'},
        'solution_id': {'key': 'properties.solutionId', 'type': 'str'},
        'workload_type': {'key': 'properties.workloadType', 'type': 'str'},
        'component_name': {'key': 'properties.componentName', 'type': 'str'},
        'component_type_id': {'key': 'properties.componentTypeId', 'type': 'str'},
        'component_type_name': {'key': 'properties.componentTypeName', 'type': 'str'},
        'component_type_group_category': {'key': 'properties.componentTypeGroupCategory', 'type': 'str'},
        'health_state': {'key': 'properties.healthState', 'type': 'HealthState'},
        'health_state_category': {'key': 'properties.healthStateCategory', 'type': 'str'},
        'health_state_changes_start_time': {'key': 'properties.healthStateChangesStartTime', 'type': 'iso-8601'},
        'health_state_changes_end_time': {'key': 'properties.healthStateChangesEndTime', 'type': 'iso-8601'},
        'last_health_state_change_time': {'key': 'properties.lastHealthStateChangeTime', 'type': 'iso-8601'},
        'vm_id': {'key': 'properties.vmId', 'type': 'str'},
        'vm_name': {'key': 'properties.vmName', 'type': 'str'},
        'vm_tags': {'key': 'properties.vmTags', 'type': '{str}'},
        'aggregate_properties': {'key': 'properties.aggregateProperties', 'type': '{str}'},
        'children': {'key': 'properties.children', 'type': '[Component]'},
    }

    def __init__(self, **kwargs):
        super(Component, self).__init__(**kwargs)
        self.etag = None
        self.workspace_id = None
        self.solution_id = None
        self.workload_type = None
        self.component_name = None
        self.component_type_id = None
        self.component_type_name = None
        self.component_type_group_category = None
        self.health_state = None
        self.health_state_category = None
        self.health_state_changes_start_time = None
        self.health_state_changes_end_time = None
        self.last_health_state_change_time = None
        self.vm_id = None
        self.vm_name = None
        self.vm_tags = None
        self.aggregate_properties = None
        self.children = None
