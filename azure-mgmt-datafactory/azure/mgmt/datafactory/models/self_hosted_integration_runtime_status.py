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

from .integration_runtime_status import IntegrationRuntimeStatus


class SelfHostedIntegrationRuntimeStatus(IntegrationRuntimeStatus):
    """Self-hosted integration runtime status.

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
    :ivar task_queue_id: The task queue id of the integration runtime.
    :vartype task_queue_id: str
    :ivar internal_channel_encryption: It is used to set the encryption mode
     for node-node communication channel (when more than 2 self-hosted
     integration runtime nodes exist). Possible values include: 'NotSet',
     'SslEncrypted', 'NotEncrypted'
    :vartype internal_channel_encryption: str or
     ~azure.mgmt.datafactory.models.IntegrationRuntimeInternalChannelEncryptionMode
    :ivar version: Version of the integration runtime.
    :vartype version: str
    :param nodes: The list of nodes for this integration runtime.
    :type nodes:
     list[~azure.mgmt.datafactory.models.SelfHostedIntegrationRuntimeNode]
    :ivar scheduled_update_date: The date at which the integration runtime
     will be scheduled to update, in ISO8601 format.
    :vartype scheduled_update_date: datetime
    :ivar update_delay_offset: The time in the date scheduled by service to
     update the integration runtime, e.g., PT03H is 3 hours
    :vartype update_delay_offset: str
    :ivar local_time_zone_offset: The local time zone offset in hours.
    :vartype local_time_zone_offset: str
    :ivar capabilities: Object with additional information about integration
     runtime capabilities.
    :vartype capabilities: dict[str, str]
    :ivar service_urls: The URLs for the services used in integration runtime
     backend service.
    :vartype service_urls: list[str]
    :ivar auto_update: Whether Self-hosted integration runtime auto update has
     been turned on. Possible values include: 'On', 'Off'
    :vartype auto_update: str or
     ~azure.mgmt.datafactory.models.IntegrationRuntimeAutoUpdate
    :ivar version_status: Status of the integration runtime version.
    :vartype version_status: str
    :param links: The list of linked integration runtimes that are created to
     share with this integration runtime.
    :type links: list[~azure.mgmt.datafactory.models.LinkedIntegrationRuntime]
    :ivar shared_with_factories: The MSI-s of the data factories to which the
     integration runtime is shared.
    :vartype shared_with_factories: list[str]
    :ivar pushed_version: The version that the integration runtime is going to
     update to.
    :vartype pushed_version: str
    :ivar latest_version: The latest version on download center.
    :vartype latest_version: str
    """

    _validation = {
        'data_factory_name': {'readonly': True},
        'state': {'readonly': True},
        'type': {'required': True},
        'create_time': {'readonly': True},
        'task_queue_id': {'readonly': True},
        'internal_channel_encryption': {'readonly': True},
        'version': {'readonly': True},
        'scheduled_update_date': {'readonly': True},
        'update_delay_offset': {'readonly': True},
        'local_time_zone_offset': {'readonly': True},
        'capabilities': {'readonly': True},
        'service_urls': {'readonly': True},
        'auto_update': {'readonly': True},
        'version_status': {'readonly': True},
        'shared_with_factories': {'readonly': True},
        'pushed_version': {'readonly': True},
        'latest_version': {'readonly': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'data_factory_name': {'key': 'dataFactoryName', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'create_time': {'key': 'typeProperties.createTime', 'type': 'iso-8601'},
        'task_queue_id': {'key': 'typeProperties.taskQueueId', 'type': 'str'},
        'internal_channel_encryption': {'key': 'typeProperties.internalChannelEncryption', 'type': 'str'},
        'version': {'key': 'typeProperties.version', 'type': 'str'},
        'nodes': {'key': 'typeProperties.nodes', 'type': '[SelfHostedIntegrationRuntimeNode]'},
        'scheduled_update_date': {'key': 'typeProperties.scheduledUpdateDate', 'type': 'iso-8601'},
        'update_delay_offset': {'key': 'typeProperties.updateDelayOffset', 'type': 'str'},
        'local_time_zone_offset': {'key': 'typeProperties.localTimeZoneOffset', 'type': 'str'},
        'capabilities': {'key': 'typeProperties.capabilities', 'type': '{str}'},
        'service_urls': {'key': 'typeProperties.serviceUrls', 'type': '[str]'},
        'auto_update': {'key': 'typeProperties.autoUpdate', 'type': 'str'},
        'version_status': {'key': 'typeProperties.versionStatus', 'type': 'str'},
        'links': {'key': 'typeProperties.links', 'type': '[LinkedIntegrationRuntime]'},
        'shared_with_factories': {'key': 'typeProperties.sharedWithFactories', 'type': '[str]'},
        'pushed_version': {'key': 'typeProperties.pushedVersion', 'type': 'str'},
        'latest_version': {'key': 'typeProperties.latestVersion', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SelfHostedIntegrationRuntimeStatus, self).__init__(**kwargs)
        self.create_time = None
        self.task_queue_id = None
        self.internal_channel_encryption = None
        self.version = None
        self.nodes = kwargs.get('nodes', None)
        self.scheduled_update_date = None
        self.update_delay_offset = None
        self.local_time_zone_offset = None
        self.capabilities = None
        self.service_urls = None
        self.auto_update = None
        self.version_status = None
        self.links = kwargs.get('links', None)
        self.shared_with_factories = None
        self.pushed_version = None
        self.latest_version = None
        self.type = 'SelfHosted'
