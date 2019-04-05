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

from .resource import Resource


class ClusterUpdate(Resource):
    """Class representing an update to a Kusto cluster.

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
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param location: Resource location.
    :type location: str
    :param sku: The SKU of the cluster.
    :type sku: ~azure.mgmt.kusto.models.AzureSku
    :ivar state: The state of the resource. Possible values include:
     'Creating', 'Unavailable', 'Running', 'Deleting', 'Deleted', 'Stopping',
     'Stopped', 'Starting', 'Updating'
    :vartype state: str or ~azure.mgmt.kusto.models.State
    :ivar provisioning_state: The provisioned state of the resource. Possible
     values include: 'Running', 'Creating', 'Deleting', 'Succeeded', 'Failed'
    :vartype provisioning_state: str or
     ~azure.mgmt.kusto.models.ProvisioningState
    :ivar uri: The cluster URI.
    :vartype uri: str
    :ivar data_ingestion_uri: The cluster data ingestion URI.
    :vartype data_ingestion_uri: str
    :param trusted_external_tenants: The cluster's external tenants.
    :type trusted_external_tenants:
     list[~azure.mgmt.kusto.models.TrustedExternalTenant]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'state': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'uri': {'readonly': True},
        'data_ingestion_uri': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'AzureSku'},
        'state': {'key': 'properties.state', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'uri': {'key': 'properties.uri', 'type': 'str'},
        'data_ingestion_uri': {'key': 'properties.dataIngestionUri', 'type': 'str'},
        'trusted_external_tenants': {'key': 'properties.trustedExternalTenants', 'type': '[TrustedExternalTenant]'},
    }

    def __init__(self, **kwargs):
        super(ClusterUpdate, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.location = kwargs.get('location', None)
        self.sku = kwargs.get('sku', None)
        self.state = None
        self.provisioning_state = None
        self.uri = None
        self.data_ingestion_uri = None
        self.trusted_external_tenants = kwargs.get('trusted_external_tenants', None)
