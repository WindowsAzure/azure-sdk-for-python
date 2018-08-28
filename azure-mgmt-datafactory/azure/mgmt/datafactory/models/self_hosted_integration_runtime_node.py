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


class SelfHostedIntegrationRuntimeNode(Model):
    """Properties of Self-hosted integration runtime node.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :ivar node_name: Name of the integration runtime node.
    :vartype node_name: str
    :ivar machine_name: Machine name of the integration runtime node.
    :vartype machine_name: str
    :ivar host_service_uri: URI for the host machine of the integration
     runtime.
    :vartype host_service_uri: str
    :ivar status: Status of the integration runtime node. Possible values
     include: 'NeedRegistration', 'Online', 'Limited', 'Offline', 'Upgrading',
     'Initializing', 'InitializeFailed'
    :vartype status: str or
     ~azure.mgmt.datafactory.models.SelfHostedIntegrationRuntimeNodeStatus
    :ivar capabilities: The integration runtime capabilities dictionary
    :vartype capabilities: dict[str, str]
    :ivar version_status: Status of the integration runtime node version.
    :vartype version_status: str
    :ivar version: Version of the integration runtime node.
    :vartype version: str
    :ivar register_time: The time at which the integration runtime node was
     registered in ISO8601 format.
    :vartype register_time: datetime
    :ivar last_connect_time: The most recent time at which the integration
     runtime was connected in ISO8601 format.
    :vartype last_connect_time: datetime
    :ivar expiry_time: The time at which the integration runtime will expire
     in ISO8601 format.
    :vartype expiry_time: datetime
    :ivar last_start_time: The time the node last started up.
    :vartype last_start_time: datetime
    :ivar last_stop_time: The integration runtime node last stop time.
    :vartype last_stop_time: datetime
    :ivar last_update_result: The result of the last integration runtime node
     update. Possible values include: 'None', 'Succeed', 'Fail'
    :vartype last_update_result: str or
     ~azure.mgmt.datafactory.models.IntegrationRuntimeUpdateResult
    :ivar last_start_update_time: The last time for the integration runtime
     node update start.
    :vartype last_start_update_time: datetime
    :ivar last_end_update_time: The last time for the integration runtime node
     update end.
    :vartype last_end_update_time: datetime
    :ivar is_active_dispatcher: Indicates whether this node is the active
     dispatcher for integration runtime requests.
    :vartype is_active_dispatcher: bool
    :ivar concurrent_jobs_limit: Maximum concurrent jobs on the integration
     runtime node.
    :vartype concurrent_jobs_limit: int
    :ivar max_concurrent_jobs: The maximum concurrent jobs in this integration
     runtime.
    :vartype max_concurrent_jobs: int
    """

    _validation = {
        'node_name': {'readonly': True},
        'machine_name': {'readonly': True},
        'host_service_uri': {'readonly': True},
        'status': {'readonly': True},
        'capabilities': {'readonly': True},
        'version_status': {'readonly': True},
        'version': {'readonly': True},
        'register_time': {'readonly': True},
        'last_connect_time': {'readonly': True},
        'expiry_time': {'readonly': True},
        'last_start_time': {'readonly': True},
        'last_stop_time': {'readonly': True},
        'last_update_result': {'readonly': True},
        'last_start_update_time': {'readonly': True},
        'last_end_update_time': {'readonly': True},
        'is_active_dispatcher': {'readonly': True},
        'concurrent_jobs_limit': {'readonly': True},
        'max_concurrent_jobs': {'readonly': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'node_name': {'key': 'nodeName', 'type': 'str'},
        'machine_name': {'key': 'machineName', 'type': 'str'},
        'host_service_uri': {'key': 'hostServiceUri', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'capabilities': {'key': 'capabilities', 'type': '{str}'},
        'version_status': {'key': 'versionStatus', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
        'register_time': {'key': 'registerTime', 'type': 'iso-8601'},
        'last_connect_time': {'key': 'lastConnectTime', 'type': 'iso-8601'},
        'expiry_time': {'key': 'expiryTime', 'type': 'iso-8601'},
        'last_start_time': {'key': 'lastStartTime', 'type': 'iso-8601'},
        'last_stop_time': {'key': 'lastStopTime', 'type': 'iso-8601'},
        'last_update_result': {'key': 'lastUpdateResult', 'type': 'str'},
        'last_start_update_time': {'key': 'lastStartUpdateTime', 'type': 'iso-8601'},
        'last_end_update_time': {'key': 'lastEndUpdateTime', 'type': 'iso-8601'},
        'is_active_dispatcher': {'key': 'isActiveDispatcher', 'type': 'bool'},
        'concurrent_jobs_limit': {'key': 'concurrentJobsLimit', 'type': 'int'},
        'max_concurrent_jobs': {'key': 'maxConcurrentJobs', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(SelfHostedIntegrationRuntimeNode, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.node_name = None
        self.machine_name = None
        self.host_service_uri = None
        self.status = None
        self.capabilities = None
        self.version_status = None
        self.version = None
        self.register_time = None
        self.last_connect_time = None
        self.expiry_time = None
        self.last_start_time = None
        self.last_stop_time = None
        self.last_update_result = None
        self.last_start_update_time = None
        self.last_end_update_time = None
        self.is_active_dispatcher = None
        self.concurrent_jobs_limit = None
        self.max_concurrent_jobs = None
