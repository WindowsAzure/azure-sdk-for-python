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


class DatabaseAccountCreateUpdateParameters(Resource):
    """Parameters to create and update Cosmos DB database accounts.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The unique resource identifier of the database account.
    :vartype id: str
    :ivar name: The name of the database account.
    :vartype name: str
    :ivar type: The type of Azure resource.
    :vartype type: str
    :param location: The location of the resource group to which the resource
     belongs.
    :type location: str
    :param tags:
    :type tags: dict[str, str]
    :param kind: Indicates the type of database account. This can only be set
     at database account creation. Possible values include: 'GlobalDocumentDB',
     'MongoDB', 'Parse'. Default value: "GlobalDocumentDB" .
    :type kind: str or ~azure.mgmt.cosmosdb.models.DatabaseAccountKind
    :param consistency_policy: The consistency policy for the Cosmos DB
     account.
    :type consistency_policy: ~azure.mgmt.cosmosdb.models.ConsistencyPolicy
    :param locations: An array that contains the georeplication locations
     enabled for the Cosmos DB account.
    :type locations: list[~azure.mgmt.cosmosdb.models.Location]
    :ivar database_account_offer_type:  Default value: "Standard" .
    :vartype database_account_offer_type: str
    :param ip_range_filter: Cosmos DB Firewall Support: This value specifies
     the set of IP addresses or IP address ranges in CIDR form to be included
     as the allowed list of client IPs for a given database account. IP
     addresses/ranges must be comma separated and must not contain any spaces.
    :type ip_range_filter: str
    :param enable_automatic_failover: Enables automatic failover of the write
     region in the rare event that the region is unavailable due to an outage.
     Automatic failover will result in a new write region for the account and
     is chosen based on the failover priorities configured for the account.
    :type enable_automatic_failover: bool
    :param capabilities: List of Cosmos DB capabilities for the account
    :type capabilities: list[~azure.mgmt.cosmosdb.models.Capability]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'locations': {'required': True},
        'database_account_offer_type': {'required': True, 'constant': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'kind': {'key': 'kind', 'type': 'str'},
        'consistency_policy': {'key': 'properties.consistencyPolicy', 'type': 'ConsistencyPolicy'},
        'locations': {'key': 'properties.locations', 'type': '[Location]'},
        'database_account_offer_type': {'key': 'properties.databaseAccountOfferType', 'type': 'str'},
        'ip_range_filter': {'key': 'properties.ipRangeFilter', 'type': 'str'},
        'enable_automatic_failover': {'key': 'properties.enableAutomaticFailover', 'type': 'bool'},
        'capabilities': {'key': 'properties.capabilities', 'type': '[Capability]'},
    }

    database_account_offer_type = "Standard"

    def __init__(self, location, locations, tags=None, kind="GlobalDocumentDB", consistency_policy=None, ip_range_filter=None, enable_automatic_failover=None, capabilities=None):
        super(DatabaseAccountCreateUpdateParameters, self).__init__(location=location, tags=tags)
        self.kind = kind
        self.consistency_policy = consistency_policy
        self.locations = locations
        self.ip_range_filter = ip_range_filter
        self.enable_automatic_failover = enable_automatic_failover
        self.capabilities = capabilities
