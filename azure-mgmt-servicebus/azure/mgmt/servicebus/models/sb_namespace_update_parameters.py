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

from .resource_namespace_patch import ResourceNamespacePatch


class SBNamespaceUpdateParameters(ResourceNamespacePatch):
    """Description of a namespace resource.

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
    :param sku: Porperties of Sku
    :type sku: ~azure.mgmt.servicebus.models.SBSku
    :ivar provisioning_state: Provisioning state of the namespace.
    :vartype provisioning_state: str
    :ivar created_at: The time the namespace was created.
    :vartype created_at: datetime
    :ivar updated_at: The time the namespace was updated.
    :vartype updated_at: datetime
    :ivar service_bus_endpoint: Endpoint you can use to perform Service Bus
     operations.
    :vartype service_bus_endpoint: str
    :ivar metric_id: Identifier for Azure Insights metrics
    :vartype metric_id: str
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
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'SBSku'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'created_at': {'key': 'properties.createdAt', 'type': 'iso-8601'},
        'updated_at': {'key': 'properties.updatedAt', 'type': 'iso-8601'},
        'service_bus_endpoint': {'key': 'properties.serviceBusEndpoint', 'type': 'str'},
        'metric_id': {'key': 'properties.metricId', 'type': 'str'},
    }

    def __init__(self, location=None, tags=None, sku=None):
        super(SBNamespaceUpdateParameters, self).__init__(location=location, tags=tags)
        self.sku = sku
        self.provisioning_state = None
        self.created_at = None
        self.updated_at = None
        self.service_bus_endpoint = None
        self.metric_id = None
