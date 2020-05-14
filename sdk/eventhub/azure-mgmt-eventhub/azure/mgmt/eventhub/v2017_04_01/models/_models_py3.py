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


class AccessKeys(Model):
    """Namespace/EventHub Connection String.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar primary_connection_string: Primary connection string of the created
     namespace AuthorizationRule.
    :vartype primary_connection_string: str
    :ivar secondary_connection_string: Secondary connection string of the
     created namespace AuthorizationRule.
    :vartype secondary_connection_string: str
    :ivar alias_primary_connection_string: Primary connection string of the
     alias if GEO DR is enabled
    :vartype alias_primary_connection_string: str
    :ivar alias_secondary_connection_string: Secondary  connection string of
     the alias if GEO DR is enabled
    :vartype alias_secondary_connection_string: str
    :ivar primary_key: A base64-encoded 256-bit primary key for signing and
     validating the SAS token.
    :vartype primary_key: str
    :ivar secondary_key: A base64-encoded 256-bit primary key for signing and
     validating the SAS token.
    :vartype secondary_key: str
    :ivar key_name: A string that describes the AuthorizationRule.
    :vartype key_name: str
    """

    _validation = {
        'primary_connection_string': {'readonly': True},
        'secondary_connection_string': {'readonly': True},
        'alias_primary_connection_string': {'readonly': True},
        'alias_secondary_connection_string': {'readonly': True},
        'primary_key': {'readonly': True},
        'secondary_key': {'readonly': True},
        'key_name': {'readonly': True},
    }

    _attribute_map = {
        'primary_connection_string': {'key': 'primaryConnectionString', 'type': 'str'},
        'secondary_connection_string': {'key': 'secondaryConnectionString', 'type': 'str'},
        'alias_primary_connection_string': {'key': 'aliasPrimaryConnectionString', 'type': 'str'},
        'alias_secondary_connection_string': {'key': 'aliasSecondaryConnectionString', 'type': 'str'},
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'key_name': {'key': 'keyName', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(AccessKeys, self).__init__(**kwargs)
        self.primary_connection_string = None
        self.secondary_connection_string = None
        self.alias_primary_connection_string = None
        self.alias_secondary_connection_string = None
        self.primary_key = None
        self.secondary_key = None
        self.key_name = None


class Resource(Model):
    """The resource definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
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


class ArmDisasterRecovery(Resource):
    """Single item in List or Get Alias(Disaster Recovery configuration)
    operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar provisioning_state: Provisioning state of the Alias(Disaster
     Recovery configuration) - possible values 'Accepted' or 'Succeeded' or
     'Failed'. Possible values include: 'Accepted', 'Succeeded', 'Failed'
    :vartype provisioning_state: str or
     ~azure.mgmt.eventhub.v2017_04_01.models.ProvisioningStateDR
    :param partner_namespace: ARM Id of the Primary/Secondary eventhub
     namespace name, which is part of GEO DR pairing
    :type partner_namespace: str
    :param alternate_name: Alternate name specified when alias and namespace
     names are same.
    :type alternate_name: str
    :ivar role: role of namespace in GEO DR - possible values 'Primary' or
     'PrimaryNotReplicating' or 'Secondary'. Possible values include:
     'Primary', 'PrimaryNotReplicating', 'Secondary'
    :vartype role: str or
     ~azure.mgmt.eventhub.v2017_04_01.models.RoleDisasterRecovery
    :ivar pending_replication_operations_count: Number of entities pending to
     be replicated.
    :vartype pending_replication_operations_count: long
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'role': {'readonly': True},
        'pending_replication_operations_count': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'ProvisioningStateDR'},
        'partner_namespace': {'key': 'properties.partnerNamespace', 'type': 'str'},
        'alternate_name': {'key': 'properties.alternateName', 'type': 'str'},
        'role': {'key': 'properties.role', 'type': 'RoleDisasterRecovery'},
        'pending_replication_operations_count': {'key': 'properties.pendingReplicationOperationsCount', 'type': 'long'},
    }

    def __init__(self, *, partner_namespace: str=None, alternate_name: str=None, **kwargs) -> None:
        super(ArmDisasterRecovery, self).__init__(**kwargs)
        self.provisioning_state = None
        self.partner_namespace = partner_namespace
        self.alternate_name = alternate_name
        self.role = None
        self.pending_replication_operations_count = None


class AuthorizationRule(Resource):
    """Single item in a List or Get AuthorizationRule operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param rights: Required. The rights associated with the rule.
    :type rights: list[str or
     ~azure.mgmt.eventhub.v2017_04_01.models.AccessRights]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'rights': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'rights': {'key': 'properties.rights', 'type': '[str]'},
    }

    def __init__(self, *, rights, **kwargs) -> None:
        super(AuthorizationRule, self).__init__(**kwargs)
        self.rights = rights


class CaptureDescription(Model):
    """Properties to configure capture description for eventhub.

    :param enabled: A value that indicates whether capture description is
     enabled.
    :type enabled: bool
    :param encoding: Enumerates the possible values for the encoding format of
     capture description. Note: 'AvroDeflate' will be deprecated in New API
     Version. Possible values include: 'Avro', 'AvroDeflate'
    :type encoding: str or
     ~azure.mgmt.eventhub.v2017_04_01.models.EncodingCaptureDescription
    :param interval_in_seconds: The time window allows you to set the
     frequency with which the capture to Azure Blobs will happen, value should
     between 60 to 900 seconds
    :type interval_in_seconds: int
    :param size_limit_in_bytes: The size window defines the amount of data
     built up in your Event Hub before an capture operation, value should be
     between 10485760 to 524288000 bytes
    :type size_limit_in_bytes: int
    :param destination: Properties of Destination where capture will be
     stored. (Storage Account, Blob Names)
    :type destination: ~azure.mgmt.eventhub.v2017_04_01.models.Destination
    :param skip_empty_archives: A value that indicates whether to Skip Empty
     Archives
    :type skip_empty_archives: bool
    """

    _validation = {
        'interval_in_seconds': {'maximum': 900, 'minimum': 60},
        'size_limit_in_bytes': {'maximum': 524288000, 'minimum': 10485760},
    }

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'encoding': {'key': 'encoding', 'type': 'EncodingCaptureDescription'},
        'interval_in_seconds': {'key': 'intervalInSeconds', 'type': 'int'},
        'size_limit_in_bytes': {'key': 'sizeLimitInBytes', 'type': 'int'},
        'destination': {'key': 'destination', 'type': 'Destination'},
        'skip_empty_archives': {'key': 'skipEmptyArchives', 'type': 'bool'},
    }

    def __init__(self, *, enabled: bool=None, encoding=None, interval_in_seconds: int=None, size_limit_in_bytes: int=None, destination=None, skip_empty_archives: bool=None, **kwargs) -> None:
        super(CaptureDescription, self).__init__(**kwargs)
        self.enabled = enabled
        self.encoding = encoding
        self.interval_in_seconds = interval_in_seconds
        self.size_limit_in_bytes = size_limit_in_bytes
        self.destination = destination
        self.skip_empty_archives = skip_empty_archives


class CheckNameAvailabilityParameter(Model):
    """Parameter supplied to check Namespace name availability operation .

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Name to check the namespace name availability
    :type name: str
    """

    _validation = {
        'name': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, name: str, **kwargs) -> None:
        super(CheckNameAvailabilityParameter, self).__init__(**kwargs)
        self.name = name


class CheckNameAvailabilityResult(Model):
    """The Result of the CheckNameAvailability operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar message: The detailed info regarding the reason associated with the
     Namespace.
    :vartype message: str
    :param name_available: Value indicating Namespace is availability, true if
     the Namespace is available; otherwise, false.
    :type name_available: bool
    :param reason: The reason for unavailability of a Namespace. Possible
     values include: 'None', 'InvalidName', 'SubscriptionIsDisabled',
     'NameInUse', 'NameInLockdown', 'TooManyNamespaceInCurrentSubscription'
    :type reason: str or
     ~azure.mgmt.eventhub.v2017_04_01.models.UnavailableReason
    """

    _validation = {
        'message': {'readonly': True},
    }

    _attribute_map = {
        'message': {'key': 'message', 'type': 'str'},
        'name_available': {'key': 'nameAvailable', 'type': 'bool'},
        'reason': {'key': 'reason', 'type': 'UnavailableReason'},
    }

    def __init__(self, *, name_available: bool=None, reason=None, **kwargs) -> None:
        super(CheckNameAvailabilityResult, self).__init__(**kwargs)
        self.message = None
        self.name_available = name_available
        self.reason = reason


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class ConsumerGroup(Resource):
    """Single item in List or Get Consumer group operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar created_at: Exact time the message was created.
    :vartype created_at: datetime
    :ivar updated_at: The exact time the message was updated.
    :vartype updated_at: datetime
    :param user_metadata: User Metadata is a placeholder to store user-defined
     string data with maximum length 1024. e.g. it can be used to store
     descriptive data, such as list of teams and their contact information also
     user-defined configuration settings can be stored.
    :type user_metadata: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created_at': {'readonly': True},
        'updated_at': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'user_metadata': {'key': 'properties.userMetadata', 'type': 'str'},
    }

    def __init__(self, *, user_metadata: str=None, **kwargs) -> None:
        super(ConsumerGroup, self).__init__(**kwargs)
        self.created_at = None
        self.updated_at = None
        self.user_metadata = user_metadata


class Destination(Model):
    """Capture storage details for capture description.

    :param name: Name for capture destination
    :type name: str
    :param storage_account_resource_id: Resource id of the storage account to
     be used to create the blobs
    :type storage_account_resource_id: str
    :param blob_container: Blob container Name
    :type blob_container: str
    :param archive_name_format: Blob naming convention for archive, e.g.
     {Namespace}/{EventHub}/{PartitionId}/{Year}/{Month}/{Day}/{Hour}/{Minute}/{Second}.
     Here all the parameters (Namespace,EventHub .. etc) are mandatory
     irrespective of order
    :type archive_name_format: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'storage_account_resource_id': {'key': 'properties.storageAccountResourceId', 'type': 'str'},
        'blob_container': {'key': 'properties.blobContainer', 'type': 'str'},
        'archive_name_format': {'key': 'properties.archiveNameFormat', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, storage_account_resource_id: str=None, blob_container: str=None, archive_name_format: str=None, **kwargs) -> None:
        super(Destination, self).__init__(**kwargs)
        self.name = name
        self.storage_account_resource_id = storage_account_resource_id
        self.blob_container = blob_container
        self.archive_name_format = archive_name_format


class TrackedResource(Resource):
    """Definition of resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
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
    }

    def __init__(self, *, location: str=None, tags=None, **kwargs) -> None:
        super(TrackedResource, self).__init__(**kwargs)
        self.location = location
        self.tags = tags


class EHNamespace(TrackedResource):
    """Single Namespace item in List or Get Operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param sku: Properties of sku resource
    :type sku: ~azure.mgmt.eventhub.v2017_04_01.models.Sku
    :ivar provisioning_state: Provisioning state of the Namespace.
    :vartype provisioning_state: str
    :ivar created_at: The time the Namespace was created.
    :vartype created_at: datetime
    :ivar updated_at: The time the Namespace was updated.
    :vartype updated_at: datetime
    :ivar service_bus_endpoint: Endpoint you can use to perform Service Bus
     operations.
    :vartype service_bus_endpoint: str
    :ivar metric_id: Identifier for Azure Insights metrics.
    :vartype metric_id: str
    :param is_auto_inflate_enabled: Value that indicates whether AutoInflate
     is enabled for eventhub namespace.
    :type is_auto_inflate_enabled: bool
    :param maximum_throughput_units: Upper limit of throughput units when
     AutoInflate is enabled, value should be within 0 to 20 throughput units. (
     '0' if AutoInflateEnabled = true)
    :type maximum_throughput_units: int
    :param kafka_enabled: Value that indicates whether Kafka is enabled for
     eventhub namespace.
    :type kafka_enabled: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'created_at': {'readonly': True},
        'updated_at': {'readonly': True},
        'service_bus_endpoint': {'readonly': True},
        'metric_id': {'readonly': True},
        'maximum_throughput_units': {'maximum': 20, 'minimum': 0},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'service_bus_endpoint': {'key': 'properties.serviceBusEndpoint', 'type': 'str'},
        'metric_id': {'key': 'properties.metricId', 'type': 'str'},
        'is_auto_inflate_enabled': {'key': 'properties.isAutoInflateEnabled', 'type': 'bool'},
        'maximum_throughput_units': {'key': 'properties.maximumThroughputUnits', 'type': 'int'},
        'kafka_enabled': {'key': 'properties.kafkaEnabled', 'type': 'bool'},
    }

    def __init__(self, *, location: str=None, tags=None, sku=None, is_auto_inflate_enabled: bool=None, maximum_throughput_units: int=None, kafka_enabled: bool=None, **kwargs) -> None:
        super(EHNamespace, self).__init__(location=location, tags=tags, **kwargs)
        self.sku = sku
        self.provisioning_state = None
        self.created_at = None
        self.updated_at = None
        self.service_bus_endpoint = None
        self.metric_id = None
        self.is_auto_inflate_enabled = is_auto_inflate_enabled
        self.maximum_throughput_units = maximum_throughput_units
        self.kafka_enabled = kafka_enabled


class ErrorResponse(Model):
    """Error response indicates Event Hub service is not able to process the
    incoming request. The reason is provided in the error message.

    :param code: Error code.
    :type code: str
    :param message: Error message indicating why the operation failed.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(self, *, code: str=None, message: str=None, **kwargs) -> None:
        super(ErrorResponse, self).__init__(**kwargs)
        self.code = code
        self.message = message


class ErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ErrorResponseException, self).__init__(deserialize, response, 'ErrorResponse', *args)


class Eventhub(Resource):
    """Single item in List or Get Event Hub operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar partition_ids: Current number of shards on the Event Hub.
    :vartype partition_ids: list[str]
    :ivar created_at: Exact time the Event Hub was created.
    :vartype created_at: datetime
    :ivar updated_at: The exact time the message was updated.
    :vartype updated_at: datetime
    :param message_retention_in_days: Number of days to retain the events for
     this Event Hub, value should be 1 to 7 days
    :type message_retention_in_days: long
    :param partition_count: Number of partitions created for the Event Hub,
     allowed values are from 1 to 32 partitions.
    :type partition_count: long
    :param status: Enumerates the possible values for the status of the Event
     Hub. Possible values include: 'Active', 'Disabled', 'Restoring',
     'SendDisabled', 'ReceiveDisabled', 'Creating', 'Deleting', 'Renaming',
     'Unknown'
    :type status: str or ~azure.mgmt.eventhub.v2017_04_01.models.EntityStatus
    :param capture_description: Properties of capture description
    :type capture_description:
     ~azure.mgmt.eventhub.v2017_04_01.models.CaptureDescription
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'partition_ids': {'readonly': True},
        'created_at': {'readonly': True},
        'updated_at': {'readonly': True},
        'message_retention_in_days': {'minimum': 1},
        'partition_count': {'minimum': 1},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'partition_ids': {'key': 'properties.partitionIds', 'type': '[str]'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'message_retention_in_days': {'key': 'properties.messageRetentionInDays', 'type': 'long'},
        'partition_count': {'key': 'properties.partitionCount', 'type': 'long'},
        'status': {'key': 'properties.status', 'type': 'EntityStatus'},
        'capture_description': {'key': 'properties.captureDescription', 'type': 'CaptureDescription'},
    }

    def __init__(self, *, message_retention_in_days: int=None, partition_count: int=None, status=None, capture_description=None, **kwargs) -> None:
        super(Eventhub, self).__init__(**kwargs)
        self.partition_ids = None
        self.created_at = None
        self.updated_at = None
        self.message_retention_in_days = message_retention_in_days
        self.partition_count = partition_count
        self.status = status
        self.capture_description = capture_description


class MessagingPlan(TrackedResource):
    """Messaging Plan for the namespace.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :ivar sku: Sku type
    :vartype sku: int
    :ivar selected_event_hub_unit: Selected event hub unit
    :vartype selected_event_hub_unit: int
    :ivar updated_at: The exact time the messaging plan was updated.
    :vartype updated_at: datetime
    :ivar revision: revision number
    :vartype revision: long
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'sku': {'readonly': True},
        'selected_event_hub_unit': {'readonly': True},
        'updated_at': {'readonly': True},
        'revision': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'properties.sku', 'type': 'int'},
        'selected_event_hub_unit': {'key': 'properties.selectedEventHubUnit', 'type': 'int'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'revision': {'key': 'properties.revision', 'type': 'long'},
    }

    def __init__(self, *, location: str=None, tags=None, **kwargs) -> None:
        super(MessagingPlan, self).__init__(location=location, tags=tags, **kwargs)
        self.sku = None
        self.selected_event_hub_unit = None
        self.updated_at = None
        self.revision = None


class MessagingRegions(TrackedResource):
    """Messaging Region.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param properties: Properties of Messaging Region
    :type properties:
     ~azure.mgmt.eventhub.v2017_04_01.models.MessagingRegionsProperties
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
        'properties': {'key': 'properties', 'type': 'MessagingRegionsProperties'},
    }

    def __init__(self, *, location: str=None, tags=None, properties=None, **kwargs) -> None:
        super(MessagingRegions, self).__init__(location=location, tags=tags, **kwargs)
        self.properties = properties


class MessagingRegionsProperties(Model):
    """Properties of Messaging Region.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: Region code
    :vartype code: str
    :ivar full_name: Full name of the region
    :vartype full_name: str
    """

    _validation = {
        'code': {'readonly': True},
        'full_name': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'full_name': {'key': 'fullName', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(MessagingRegionsProperties, self).__init__(**kwargs)
        self.code = None
        self.full_name = None


class NetworkRuleSet(Resource):
    """Description of NetworkRuleSet resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param default_action: Default Action for Network Rule Set. Possible
     values include: 'Allow', 'Deny'
    :type default_action: str or
     ~azure.mgmt.eventhub.v2017_04_01.models.DefaultAction
    :param virtual_network_rules: List VirtualNetwork Rules
    :type virtual_network_rules:
     list[~azure.mgmt.eventhub.v2017_04_01.models.NWRuleSetVirtualNetworkRules]
    :param ip_rules: List of IpRules
    :type ip_rules:
     list[~azure.mgmt.eventhub.v2017_04_01.models.NWRuleSetIpRules]
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
        'default_action': {'key': 'properties.defaultAction', 'type': 'str'},
        'virtual_network_rules': {'key': 'properties.virtualNetworkRules', 'type': '[NWRuleSetVirtualNetworkRules]'},
        'ip_rules': {'key': 'properties.ipRules', 'type': '[NWRuleSetIpRules]'},
    }

    def __init__(self, *, default_action=None, virtual_network_rules=None, ip_rules=None, **kwargs) -> None:
        super(NetworkRuleSet, self).__init__(**kwargs)
        self.default_action = default_action
        self.virtual_network_rules = virtual_network_rules
        self.ip_rules = ip_rules


class NWRuleSetIpRules(Model):
    """Description of NetWorkRuleSet - IpRules resource.

    :param ip_mask: IP Mask
    :type ip_mask: str
    :param action: The IP Filter Action. Possible values include: 'Allow'.
     Default value: "Allow" .
    :type action: str or
     ~azure.mgmt.eventhub.v2017_04_01.models.NetworkRuleIPAction
    """

    _attribute_map = {
        'ip_mask': {'key': 'ipMask', 'type': 'str'},
        'action': {'key': 'action', 'type': 'str'},
    }

    def __init__(self, *, ip_mask: str=None, action="Allow", **kwargs) -> None:
        super(NWRuleSetIpRules, self).__init__(**kwargs)
        self.ip_mask = ip_mask
        self.action = action


class NWRuleSetVirtualNetworkRules(Model):
    """Description of VirtualNetworkRules - NetworkRules resource.

    :param subnet: Subnet properties
    :type subnet: ~azure.mgmt.eventhub.v2017_04_01.models.Subnet
    :param ignore_missing_vnet_service_endpoint: Value that indicates whether
     to ignore missing VNet Service Endpoint
    :type ignore_missing_vnet_service_endpoint: bool
    """

    _attribute_map = {
        'subnet': {'key': 'subnet', 'type': 'Subnet'},
        'ignore_missing_vnet_service_endpoint': {'key': 'ignoreMissingVnetServiceEndpoint', 'type': 'bool'},
    }

    def __init__(self, *, subnet=None, ignore_missing_vnet_service_endpoint: bool=None, **kwargs) -> None:
        super(NWRuleSetVirtualNetworkRules, self).__init__(**kwargs)
        self.subnet = subnet
        self.ignore_missing_vnet_service_endpoint = ignore_missing_vnet_service_endpoint


class Operation(Model):
    """A Event Hub REST API operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Operation name: {provider}/{resource}/{operation}
    :vartype name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.eventhub.v2017_04_01.models.OperationDisplay
    """

    _validation = {
        'name': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(self, *, display=None, **kwargs) -> None:
        super(Operation, self).__init__(**kwargs)
        self.name = None
        self.display = display


class OperationDisplay(Model):
    """The object that represents the operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provider: Service provider: Microsoft.EventHub
    :vartype provider: str
    :ivar resource: Resource on which the operation is performed: Invoice,
     etc.
    :vartype resource: str
    :ivar operation: Operation type: Read, write, delete, etc.
    :vartype operation: str
    """

    _validation = {
        'provider': {'readonly': True},
        'resource': {'readonly': True},
        'operation': {'readonly': True},
    }

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = None
        self.resource = None
        self.operation = None


class RegenerateAccessKeyParameters(Model):
    """Parameters supplied to the Regenerate Authorization Rule operation,
    specifies which key needs to be reset.

    All required parameters must be populated in order to send to Azure.

    :param key_type: Required. The access key to regenerate. Possible values
     include: 'PrimaryKey', 'SecondaryKey'
    :type key_type: str or ~azure.mgmt.eventhub.v2017_04_01.models.KeyType
    :param key: Optional, if the key value provided, is set for KeyType or
     autogenerated Key value set for keyType
    :type key: str
    """

    _validation = {
        'key_type': {'required': True},
    }

    _attribute_map = {
        'key_type': {'key': 'keyType', 'type': 'KeyType'},
        'key': {'key': 'key', 'type': 'str'},
    }

    def __init__(self, *, key_type, key: str=None, **kwargs) -> None:
        super(RegenerateAccessKeyParameters, self).__init__(**kwargs)
        self.key_type = key_type
        self.key = key


class Sku(Model):
    """SKU parameters supplied to the create namespace operation.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Name of this SKU. Possible values include: 'Basic',
     'Standard'
    :type name: str or ~azure.mgmt.eventhub.v2017_04_01.models.SkuName
    :param tier: The billing tier of this particular SKU. Possible values
     include: 'Basic', 'Standard'
    :type tier: str or ~azure.mgmt.eventhub.v2017_04_01.models.SkuTier
    :param capacity: The Event Hubs throughput units, value should be 0 to 20
     throughput units.
    :type capacity: int
    """

    _validation = {
        'name': {'required': True},
        'capacity': {'maximum': 20, 'minimum': 0},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'int'},
    }

    def __init__(self, *, name, tier=None, capacity: int=None, **kwargs) -> None:
        super(Sku, self).__init__(**kwargs)
        self.name = name
        self.tier = tier
        self.capacity = capacity


class Subnet(Model):
    """Properties supplied for Subnet.

    All required parameters must be populated in order to send to Azure.

    :param id: Required. Resource ID of Virtual Network Subnet
    :type id: str
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(self, *, id: str, **kwargs) -> None:
        super(Subnet, self).__init__(**kwargs)
        self.id = id
