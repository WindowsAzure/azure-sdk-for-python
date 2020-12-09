# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import List, Optional

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class ErrorDetails(msrest.serialization.Model):
    """Error details.

    :param code: Error code identifying the specific error.
    :type code: str
    :param message: A human-readable error message.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        message: Optional[str] = None,
        **kwargs
    ):
        super(ErrorDetails, self).__init__(**kwargs)
        self.code = code
        self.message = message


class ErrorResponse(msrest.serialization.Model):
    """Error response.

    :param error: Error info.
    :type error: ~workload_monitor_api.models.ErrorResponseError
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponseError'},
    }

    def __init__(
        self,
        *,
        error: Optional["ErrorResponseError"] = None,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = error


class ErrorResponseError(msrest.serialization.Model):
    """Error info.

    :param code: Service-defined error code. This code serves as a sub-status for the HTTP error
     code specified in the response.
    :type code: str
    :param message: Human-readable representation of the error.
    :type message: str
    :param details: Error details.
    :type details: list[~workload_monitor_api.models.ErrorDetails]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorDetails]'},
    }

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        message: Optional[str] = None,
        details: Optional[List["ErrorDetails"]] = None,
        **kwargs
    ):
        super(ErrorResponseError, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.details = details


class Resource(msrest.serialization.Model):
    """The resource model definition for the ARM proxy resource, 'microsoft.workloadmonitor/monitors'.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The resource Id.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
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

    def __init__(
        self,
        **kwargs
    ):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class HealthMonitor(Resource):
    """Information about the monitor’s current health status.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The resource Id.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param monitor_name: Human-readable name of the monitor.
    :type monitor_name: str
    :param monitor_type: Type of the monitor.
    :type monitor_type: str
    :param monitored_object: Dynamic monitored object of the monitor.
    :type monitored_object: str
    :param parent_monitor_name: Name of the parent monitor.
    :type parent_monitor_name: str
    :ivar previous_monitor_state: Previous health state of the monitor. Possible values include:
     "Healthy", "Critical", "Warning", "Unknown", "Disabled", "None".
    :vartype previous_monitor_state: str or ~workload_monitor_api.models.HealthState
    :ivar current_monitor_state: Current health state of the monitor. Possible values include:
     "Healthy", "Critical", "Warning", "Unknown", "Disabled", "None".
    :vartype current_monitor_state: str or ~workload_monitor_api.models.HealthState
    :param evaluation_timestamp: Timestamp of the monitor's last health evaluation.
    :type evaluation_timestamp: str
    :param current_state_first_observed_timestamp: Timestamp of the monitor's last health state
     change.
    :type current_state_first_observed_timestamp: str
    :param last_reported_timestamp: Timestamp of the monitor's last reported health state.
    :type last_reported_timestamp: str
    :param evidence: Evidence validating the monitor's current health state.
    :type evidence: object
    :param monitor_configuration: The configuration settings at the time of the monitor's health
     evaluation.
    :type monitor_configuration: object
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'previous_monitor_state': {'readonly': True},
        'current_monitor_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'monitor_name': {'key': 'properties.monitorName', 'type': 'str'},
        'monitor_type': {'key': 'properties.monitorType', 'type': 'str'},
        'monitored_object': {'key': 'properties.monitoredObject', 'type': 'str'},
        'parent_monitor_name': {'key': 'properties.parentMonitorName', 'type': 'str'},
        'previous_monitor_state': {'key': 'properties.previousMonitorState', 'type': 'str'},
        'current_monitor_state': {'key': 'properties.currentMonitorState', 'type': 'str'},
        'evaluation_timestamp': {'key': 'properties.evaluationTimestamp', 'type': 'str'},
        'current_state_first_observed_timestamp': {'key': 'properties.currentStateFirstObservedTimestamp', 'type': 'str'},
        'last_reported_timestamp': {'key': 'properties.lastReportedTimestamp', 'type': 'str'},
        'evidence': {'key': 'properties.evidence', 'type': 'object'},
        'monitor_configuration': {'key': 'properties.monitorConfiguration', 'type': 'object'},
    }

    def __init__(
        self,
        *,
        monitor_name: Optional[str] = None,
        monitor_type: Optional[str] = None,
        monitored_object: Optional[str] = None,
        parent_monitor_name: Optional[str] = None,
        evaluation_timestamp: Optional[str] = None,
        current_state_first_observed_timestamp: Optional[str] = None,
        last_reported_timestamp: Optional[str] = None,
        evidence: Optional[object] = None,
        monitor_configuration: Optional[object] = None,
        **kwargs
    ):
        super(HealthMonitor, self).__init__(**kwargs)
        self.monitor_name = monitor_name
        self.monitor_type = monitor_type
        self.monitored_object = monitored_object
        self.parent_monitor_name = parent_monitor_name
        self.previous_monitor_state = None
        self.current_monitor_state = None
        self.evaluation_timestamp = evaluation_timestamp
        self.current_state_first_observed_timestamp = current_state_first_observed_timestamp
        self.last_reported_timestamp = last_reported_timestamp
        self.evidence = evidence
        self.monitor_configuration = monitor_configuration


class HealthMonitorList(msrest.serialization.Model):
    """Information about the current health statuses of the monitors.

    :param value: Array of health monitors of the virtual machine.
    :type value: list[~workload_monitor_api.models.HealthMonitor]
    :param next_link: Link to next page if the list is too long.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[HealthMonitor]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["HealthMonitor"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(HealthMonitorList, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class HealthMonitorStateChange(Resource):
    """Information about the monitor’s health state change at the provided timestamp.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The resource Id.
    :vartype id: str
    :ivar name: The resource name.
    :vartype name: str
    :ivar type: The resource type.
    :vartype type: str
    :param monitor_name: Human-readable name of the monitor.
    :type monitor_name: str
    :param monitor_type: Type of the monitor.
    :type monitor_type: str
    :param monitored_object: Dynamic monitored object of the monitor.
    :type monitored_object: str
    :param evaluation_timestamp: Timestamp of the monitor's last health evaluation.
    :type evaluation_timestamp: str
    :param current_state_first_observed_timestamp: Timestamp of the monitor's last health state
     change.
    :type current_state_first_observed_timestamp: str
    :ivar previous_monitor_state: Previous health state of the monitor. Possible values include:
     "Healthy", "Critical", "Warning", "Unknown", "Disabled", "None".
    :vartype previous_monitor_state: str or ~workload_monitor_api.models.HealthState
    :ivar current_monitor_state: Current health state of the monitor. Possible values include:
     "Healthy", "Critical", "Warning", "Unknown", "Disabled", "None".
    :vartype current_monitor_state: str or ~workload_monitor_api.models.HealthState
    :param evidence: Evidence validating the monitor's current health state.
    :type evidence: object
    :param monitor_configuration: The configuration settings at the time of the monitor's health
     evaluation.
    :type monitor_configuration: object
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'previous_monitor_state': {'readonly': True},
        'current_monitor_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'monitor_name': {'key': 'properties.monitorName', 'type': 'str'},
        'monitor_type': {'key': 'properties.monitorType', 'type': 'str'},
        'monitored_object': {'key': 'properties.monitoredObject', 'type': 'str'},
        'evaluation_timestamp': {'key': 'properties.evaluationTimestamp', 'type': 'str'},
        'current_state_first_observed_timestamp': {'key': 'properties.currentStateFirstObservedTimestamp', 'type': 'str'},
        'previous_monitor_state': {'key': 'properties.previousMonitorState', 'type': 'str'},
        'current_monitor_state': {'key': 'properties.currentMonitorState', 'type': 'str'},
        'evidence': {'key': 'properties.evidence', 'type': 'object'},
        'monitor_configuration': {'key': 'properties.monitorConfiguration', 'type': 'object'},
    }

    def __init__(
        self,
        *,
        monitor_name: Optional[str] = None,
        monitor_type: Optional[str] = None,
        monitored_object: Optional[str] = None,
        evaluation_timestamp: Optional[str] = None,
        current_state_first_observed_timestamp: Optional[str] = None,
        evidence: Optional[object] = None,
        monitor_configuration: Optional[object] = None,
        **kwargs
    ):
        super(HealthMonitorStateChange, self).__init__(**kwargs)
        self.monitor_name = monitor_name
        self.monitor_type = monitor_type
        self.monitored_object = monitored_object
        self.evaluation_timestamp = evaluation_timestamp
        self.current_state_first_observed_timestamp = current_state_first_observed_timestamp
        self.previous_monitor_state = None
        self.current_monitor_state = None
        self.evidence = evidence
        self.monitor_configuration = monitor_configuration


class HealthMonitorStateChangeList(msrest.serialization.Model):
    """Information about the health state changes of the monitor within the provided time window.

    :param value: Array of health state changes within the specified time window.
    :type value: list[~workload_monitor_api.models.HealthMonitorStateChange]
    :param next_link: Link to next page if the list is too long.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[HealthMonitorStateChange]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["HealthMonitorStateChange"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(HealthMonitorStateChangeList, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class Operation(msrest.serialization.Model):
    """Operation supported by the resource provider.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the operation being performed on this particular object.
    :type name: str
    :param display: Required. The localized display information for this particular operation or
     action.
    :type display: ~workload_monitor_api.models.OperationDisplay
    :param origin: Required. The intended executor of the operation.
    :type origin: str
    """

    _validation = {
        'name': {'required': True},
        'display': {'required': True},
        'origin': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: str,
        display: "OperationDisplay",
        origin: str,
        **kwargs
    ):
        super(Operation, self).__init__(**kwargs)
        self.name = name
        self.display = display
        self.origin = origin


class OperationDisplay(msrest.serialization.Model):
    """The localized display information for this particular operation or action.

    All required parameters must be populated in order to send to Azure.

    :param provider: Required. Operation resource provider name.
    :type provider: str
    :param resource: Required. Resource on which the operation is performed.
    :type resource: str
    :param operation: Required. Human-readable, friendly name for the operation.
    :type operation: str
    :param description: Required. Operation description.
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

    def __init__(
        self,
        *,
        provider: str,
        resource: str,
        operation: str,
        description: str,
        **kwargs
    ):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description


class OperationList(msrest.serialization.Model):
    """List of available REST API operations.

    :param value: Array of available REST API operations.
    :type value: list[~workload_monitor_api.models.Operation]
    :param next_link: Link to next page if the list is too long.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Operation]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["Operation"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(OperationList, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link
