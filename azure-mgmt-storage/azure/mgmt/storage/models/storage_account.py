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


class StorageAccount(Resource):
    """The storage account.

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
    :ivar sku: Gets the SKU.
    :vartype sku: :class:`Sku <azure.mgmt.storage.models.Sku>`
    :ivar kind: Gets the Kind. Possible values include: 'Storage',
     'BlobStorage'
    :vartype kind: str or :class:`Kind <azure.mgmt.storage.models.Kind>`
    :ivar provisioning_state: Gets the status of the storage account at the
     time the operation was called. Possible values include: 'Creating',
     'ResolvingDNS', 'Succeeded'
    :vartype provisioning_state: str or :class:`ProvisioningState
     <azure.mgmt.storage.models.ProvisioningState>`
    :ivar primary_endpoints: Gets the URLs that are used to perform a
     retrieval of a public blob, queue or table object.Note that StandardZRS
     and PremiumLRS accounts only return the blob endpoint.
    :vartype primary_endpoints: :class:`Endpoints
     <azure.mgmt.storage.models.Endpoints>`
    :ivar primary_location: Gets the location of the primary for the storage
     account.
    :vartype primary_location: str
    :ivar status_of_primary: Gets the status indicating whether the primary
     location of the storage account is available or unavailable. Possible
     values include: 'Available', 'Unavailable'
    :vartype status_of_primary: str or :class:`AccountStatus
     <azure.mgmt.storage.models.AccountStatus>`
    :ivar last_geo_failover_time: Gets the timestamp of the most recent
     instance of a failover to the secondary location. Only the most recent
     timestamp is retained. This element is not returned if there has never
     been a failover instance. Only available if the accountType is
     StandardGRS or StandardRAGRS.
    :vartype last_geo_failover_time: datetime
    :ivar secondary_location: Gets the location of the geo replicated
     secondary for the storage account. Only available if the accountType is
     StandardGRS or StandardRAGRS.
    :vartype secondary_location: str
    :ivar status_of_secondary: Gets the status indicating whether the
     secondary location of the storage account is available or unavailable.
     Only available if the accountType is StandardGRS or StandardRAGRS.
     Possible values include: 'Available', 'Unavailable'
    :vartype status_of_secondary: str or :class:`AccountStatus
     <azure.mgmt.storage.models.AccountStatus>`
    :ivar creation_time: Gets the creation date and time of the storage
     account in UTC.
    :vartype creation_time: datetime
    :ivar custom_domain: Gets the user assigned custom domain assigned to
     this storage account.
    :vartype custom_domain: :class:`CustomDomain
     <azure.mgmt.storage.models.CustomDomain>`
    :ivar secondary_endpoints: Gets the URLs that are used to perform a
     retrieval of a public blob, queue or table object from the secondary
     location of the storage account. Only available if the accountType is
     StandardRAGRS.
    :vartype secondary_endpoints: :class:`Endpoints
     <azure.mgmt.storage.models.Endpoints>`
    :ivar encryption: Gets the encryption settings on the account. If
     unspecified the account is unencrypted.
    :vartype encryption: :class:`Encryption
     <azure.mgmt.storage.models.Encryption>`
    :ivar access_tier: The access tier used for billing. Access tier cannot
     be changed more than once every 7 days (168 hours). Access tier cannot
     be set for StandardLRS, StandardGRS, StandardRAGRS, or PremiumLRS
     account types. Possible values include: 'Hot', 'Cool'
    :vartype access_tier: str or :class:`AccessTier
     <azure.mgmt.storage.models.AccessTier>`
    """ 

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'sku': {'readonly': True},
        'kind': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'primary_endpoints': {'readonly': True},
        'primary_location': {'readonly': True},
        'status_of_primary': {'readonly': True},
        'last_geo_failover_time': {'readonly': True},
        'secondary_location': {'readonly': True},
        'status_of_secondary': {'readonly': True},
        'creation_time': {'readonly': True},
        'custom_domain': {'readonly': True},
        'secondary_endpoints': {'readonly': True},
        'encryption': {'readonly': True},
        'access_tier': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'kind': {'key': 'kind', 'type': 'Kind'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'ProvisioningState'},
        'primary_endpoints': {'key': 'properties.primaryEndpoints', 'type': 'Endpoints'},
        'primary_location': {'key': 'properties.primaryLocation', 'type': 'str'},
        'status_of_primary': {'key': 'properties.statusOfPrimary', 'type': 'AccountStatus'},
        'last_geo_failover_time': {'key': 'properties.lastGeoFailoverTime', 'type': 'iso-8601'},
        'secondary_location': {'key': 'properties.secondaryLocation', 'type': 'str'},
        'status_of_secondary': {'key': 'properties.statusOfSecondary', 'type': 'AccountStatus'},
        'creation_time': {'key': 'properties.creationTime', 'type': 'iso-8601'},
        'custom_domain': {'key': 'properties.customDomain', 'type': 'CustomDomain'},
        'secondary_endpoints': {'key': 'properties.secondaryEndpoints', 'type': 'Endpoints'},
        'encryption': {'key': 'properties.encryption', 'type': 'Encryption'},
        'access_tier': {'key': 'properties.accessTier', 'type': 'AccessTier'},
    }

    def __init__(self, location=None, tags=None):
        super(StorageAccount, self).__init__(location=location, tags=tags)
        self.sku = None
        self.kind = None
        self.provisioning_state = None
        self.primary_endpoints = None
        self.primary_location = None
        self.status_of_primary = None
        self.last_geo_failover_time = None
        self.secondary_location = None
        self.status_of_secondary = None
        self.creation_time = None
        self.custom_domain = None
        self.secondary_endpoints = None
        self.encryption = None
        self.access_tier = None
