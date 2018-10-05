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

from .proxy_resource_py3 import ProxyResource


class Monitor(ProxyResource):
    """Model for Monitor.

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
    :ivar description: Description of the monitor
    :vartype description: str
    :ivar monitor_id: ID of the monitor
    :vartype monitor_id: str
    :ivar monitor_name: Name of the monitor
    :vartype monitor_name: str
    :ivar monitor_display_name: User friendly display name of the monitor
    :vartype monitor_display_name: str
    :ivar parent_monitor_name: Name of the parent monitor
    :vartype parent_monitor_name: str
    :ivar parent_monitor_display_name: User friendly display name of the
     parent monitor
    :vartype parent_monitor_display_name: str
    :ivar monitor_type: Type of the monitor. Possible values include:
     'Aggregate', 'Dependency', 'Unit'
    :vartype monitor_type: str or
     ~azure.mgmt.workloadmonitor.models.MonitorType
    :ivar monitor_category: Category of the monitor. Possible values include:
     'AvailabilityHealth', 'Configuration', 'EntityHealth',
     'PerformanceHealth', 'Security'
    :vartype monitor_category: str or
     ~azure.mgmt.workloadmonitor.models.MonitorCategory
    :ivar component_type_id: Component Type Id of monitor
    :vartype component_type_id: str
    :ivar component_type_name: Component Type Name of monitor
    :vartype component_type_name: str
    :ivar component_type_display_name: Component Type Display Name of the
     monitor
    :vartype component_type_display_name: str
    :ivar monitor_state: Is the monitor state enabled or disabled. Possible
     values include: 'Enabled', 'Disabled'
    :vartype monitor_state: str or
     ~azure.mgmt.workloadmonitor.models.MonitorState
    :ivar criteria: Collection of MonitorCriteria. For PATCH calls, instead of
     partial list, complete list of expected criteria should be passed for
     proper updation.
    :vartype criteria:
     list[~azure.mgmt.workloadmonitor.models.MonitorCriteria]
    :ivar alert_generation: Generates alerts or not. Possible values include:
     'Enabled', 'Disabled'
    :vartype alert_generation: str or
     ~azure.mgmt.workloadmonitor.models.AlertGeneration
    :ivar frequency: Frequency at which monitor condition is evaluated
    :vartype frequency: int
    :ivar lookback_duration: The duration in minutes in the past during which
     the monitor is evaluated
    :vartype lookback_duration: int
    :ivar documentation_url: URL pointing to the documentation of the monitor
    :vartype documentation_url: str
    :ivar signal_name: Name of the signal on which this monitor is configured.
    :vartype signal_name: str
    :ivar signal_type: Type of the signal on which this monitor is configured.
    :vartype signal_type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
        'description': {'readonly': True},
        'monitor_id': {'readonly': True},
        'monitor_name': {'readonly': True},
        'monitor_display_name': {'readonly': True},
        'parent_monitor_name': {'readonly': True},
        'parent_monitor_display_name': {'readonly': True},
        'monitor_type': {'readonly': True},
        'monitor_category': {'readonly': True},
        'component_type_id': {'readonly': True},
        'component_type_name': {'readonly': True},
        'component_type_display_name': {'readonly': True},
        'monitor_state': {'readonly': True},
        'criteria': {'readonly': True},
        'alert_generation': {'readonly': True},
        'frequency': {'readonly': True},
        'lookback_duration': {'readonly': True},
        'documentation_url': {'readonly': True},
        'signal_name': {'readonly': True},
        'signal_type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'monitor_id': {'key': 'properties.monitorId', 'type': 'str'},
        'monitor_name': {'key': 'properties.monitorName', 'type': 'str'},
        'monitor_display_name': {'key': 'properties.monitorDisplayName', 'type': 'str'},
        'parent_monitor_name': {'key': 'properties.parentMonitorName', 'type': 'str'},
        'parent_monitor_display_name': {'key': 'properties.parentMonitorDisplayName', 'type': 'str'},
        'monitor_type': {'key': 'properties.monitorType', 'type': 'MonitorType'},
        'monitor_category': {'key': 'properties.monitorCategory', 'type': 'MonitorCategory'},
        'component_type_id': {'key': 'properties.componentTypeId', 'type': 'str'},
        'component_type_name': {'key': 'properties.componentTypeName', 'type': 'str'},
        'component_type_display_name': {'key': 'properties.componentTypeDisplayName', 'type': 'str'},
        'monitor_state': {'key': 'properties.monitorState', 'type': 'MonitorState'},
        'criteria': {'key': 'properties.criteria', 'type': '[MonitorCriteria]'},
        'alert_generation': {'key': 'properties.alertGeneration', 'type': 'str'},
        'frequency': {'key': 'properties.frequency', 'type': 'int'},
        'lookback_duration': {'key': 'properties.lookbackDuration', 'type': 'int'},
        'documentation_url': {'key': 'properties.documentationURL', 'type': 'str'},
        'signal_name': {'key': 'properties.signalName', 'type': 'str'},
        'signal_type': {'key': 'properties.signalType', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(Monitor, self).__init__(**kwargs)
        self.etag = None
        self.description = None
        self.monitor_id = None
        self.monitor_name = None
        self.monitor_display_name = None
        self.parent_monitor_name = None
        self.parent_monitor_display_name = None
        self.monitor_type = None
        self.monitor_category = None
        self.component_type_id = None
        self.component_type_name = None
        self.component_type_display_name = None
        self.monitor_state = None
        self.criteria = None
        self.alert_generation = None
        self.frequency = None
        self.lookback_duration = None
        self.documentation_url = None
        self.signal_name = None
        self.signal_type = None
