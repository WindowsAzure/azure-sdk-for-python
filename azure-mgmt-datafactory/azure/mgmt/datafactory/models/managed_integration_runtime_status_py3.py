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

from .integration_runtime_status_py3 import IntegrationRuntimeStatus


class ManagedIntegrationRuntimeStatus(IntegrationRuntimeStatus):
    """Managed integration runtime status.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :ivar data_factory_name: The data factory name which the integration
     runtime belong to.
    :vartype data_factory_name: str
    :ivar state: The state of integration runtime. Possible values include:
     'Initial', 'Stopped', 'Started', 'Starting', 'Stopping',
     'NeedRegistration', 'Online', 'Limited', 'Offline', 'AccessDenied'
    :vartype state: str or
     ~azure.mgmt.datafactory.models.IntegrationRuntimeState
    :param type: Required. Constant filled by server.
    :type type: str
    :ivar create_time: The time at which the integration runtime was created,
     in ISO8601 format.
    :vartype create_time: datetime
    :ivar nodes: The list of nodes for managed integration runtime.
    :vartype nodes:
     list[~azure.mgmt.datafactory.models.ManagedIntegrationRuntimeNode]
    :ivar other_errors: The errors that occurred on this integration runtime.
    :vartype other_errors:
     list[~azure.mgmt.datafactory.models.ManagedIntegrationRuntimeError]
    :ivar last_operation: The last operation result that occurred on this
     integration runtime.
    :vartype last_operation:
     ~azure.mgmt.datafactory.models.ManagedIntegrationRuntimeOperationResult
    """

    _validation = {
        'data_factory_name': {'readonly': True},
        'state': {'readonly': True},
        'type': {'required': True},
        'create_time': {'readonly': True},
        'nodes': {'readonly': True},
        'other_errors': {'readonly': True},
        'last_operation': {'readonly': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'data_factory_name': {'key': 'dataFactoryName', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'create_time': {'key': 'typeProperties.createTime', 'type': 'iso-8601'},
        'nodes': {'key': 'typeProperties.nodes', 'type': '[ManagedIntegrationRuntimeNode]'},
        'other_errors': {'key': 'typeProperties.otherErrors', 'type': '[ManagedIntegrationRuntimeError]'},
        'last_operation': {'key': 'typeProperties.lastOperation', 'type': 'ManagedIntegrationRuntimeOperationResult'},
    }

    def __init__(self, *, additional_properties=None, **kwargs) -> None:
        super(ManagedIntegrationRuntimeStatus, self).__init__(additional_properties=additional_properties, **kwargs)
        self.create_time = None
        self.nodes = None
        self.other_errors = None
        self.last_operation = None
        self.type = 'Managed'
