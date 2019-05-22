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

from .tracked_resource_py3 import TrackedResource


class EHNamespace(TrackedResource):
    """Single Namespace item in List or Get Operation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param sku: Properties of sku resource
    :type sku: ~azure.mgmt.eventhub.v2018_01_01_preview.models.Sku
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
    :param zone_redundant: Enabling this property creates a Standard Event
     Hubs Namespace in regions supported availability zones.
    :type zone_redundant: bool
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
        'zone_redundant': {'key': 'properties.zoneRedundant', 'type': 'bool'},
    }

    def __init__(self, *, location: str=None, tags=None, sku=None, is_auto_inflate_enabled: bool=None, maximum_throughput_units: int=None, kafka_enabled: bool=None, zone_redundant: bool=None, **kwargs) -> None:
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
        self.zone_redundant = zone_redundant
