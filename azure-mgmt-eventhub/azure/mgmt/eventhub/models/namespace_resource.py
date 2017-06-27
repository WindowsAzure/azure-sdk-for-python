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


class NamespaceResource(TrackedResource):
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
    :type tags: dict
    :param sku:
    :type sku: :class:`Sku <azure.mgmt.eventhub.models.Sku>`
    :param status: State of the Namespace. Possible values include: 'Unknown',
     'Creating', 'Created', 'Activating', 'Enabling', 'Active', 'Disabling',
     'Disabled', 'SoftDeleting', 'SoftDeleted', 'Removing', 'Removed', 'Failed'
    :type status: str or :class:`NamespaceState
     <azure.mgmt.eventhub.models.NamespaceState>`
    :param provisioning_state: Provisioning state of the Namespace.
    :type provisioning_state: str
    :param created_at: The time the Namespace was created.
    :type created_at: datetime
    :param updated_at: The time the Namespace was updated.
    :type updated_at: datetime
    :param service_bus_endpoint: Endpoint you can use to perform Service Bus
     operations.
    :type service_bus_endpoint: str
    :ivar metric_id: Identifier for Azure Insights metrics
    :vartype metric_id: str
    :param enabled: Specifies whether this instance is enabled.
    :type enabled: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'metric_id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'status': {'key': 'properties.status', 'type': 'NamespaceState'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'service_bus_endpoint': {'key': 'properties.serviceBusEndpoint', 'type': 'str'},
        'metric_id': {'key': 'properties.metricId', 'type': 'str'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
    }

    def __init__(self, location, tags=None, sku=None, status=None, provisioning_state=None, created_at=None, updated_at=None, service_bus_endpoint=None, enabled=None):
        super(NamespaceResource, self).__init__(location=location, tags=tags)
        self.sku = sku
        self.status = status
        self.provisioning_state = provisioning_state
        self.created_at = created_at
        self.updated_at = updated_at
        self.service_bus_endpoint = service_bus_endpoint
        self.metric_id = None
        self.enabled = enabled
