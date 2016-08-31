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


class SearchServiceReadableProperties(Model):
    """Defines all the properties of an Azure Search service.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar status: The status of the Search service. Possible values include:
     'running', 'provisioning', 'deleting', 'degraded', 'disabled', 'error'
    :vartype status: str or :class:`SearchServiceStatus
     <azure.mgmt.search.models.SearchServiceStatus>`
    :ivar status_details: The details of the Search service status.
    :vartype status_details: str
    :ivar provisioning_state: The state of the last provisioning operation
     performed on the Search service. Possible values include: 'succeeded',
     'provisioning', 'failed'
    :vartype provisioning_state: str or :class:`ProvisioningState
     <azure.mgmt.search.models.ProvisioningState>`
    :param sku: The SKU of the Search Service, which determines price tier
     and capacity limits.
    :type sku: :class:`Sku <azure.mgmt.search.models.Sku>`
    :param replica_count: The number of replicas in the Search service. If
     specified, it must be a value between 1 and 6 inclusive.
    :type replica_count: int
    :param partition_count: The number of partitions in the Search service;
     if specified, it can be 1, 2, 3, 4, 6, or 12.
    :type partition_count: int
    """ 

    _validation = {
        'status': {'readonly': True},
        'status_details': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'SearchServiceStatus'},
        'status_details': {'key': 'statusDetails', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'ProvisioningState'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'replica_count': {'key': 'replicaCount', 'type': 'int'},
        'partition_count': {'key': 'partitionCount', 'type': 'int'},
    }

    def __init__(self, sku=None, replica_count=None, partition_count=None):
        self.status = None
        self.status_details = None
        self.provisioning_state = None
        self.sku = sku
        self.replica_count = replica_count
        self.partition_count = partition_count
