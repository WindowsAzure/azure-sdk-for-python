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

from .resource_py3 import Resource


class AzureFirewall(Resource):
    """Azure Firewall resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: Resource tags.
    :type tags: dict[str, str]
    :param application_rule_collections: Collection of application rule
     collections used by a Azure Firewall.
    :type application_rule_collections:
     list[~azure.mgmt.network.v2018_06_01.models.AzureFirewallApplicationRuleCollection]
    :param network_rule_collections: Collection of network rule collections
     used by a Azure Firewall.
    :type network_rule_collections:
     list[~azure.mgmt.network.v2018_06_01.models.AzureFirewallNetworkRuleCollection]
    :param ip_configurations: IP configuration of the Azure Firewall resource.
    :type ip_configurations:
     list[~azure.mgmt.network.v2018_06_01.models.AzureFirewallIPConfiguration]
    :param provisioning_state: The provisioning state of the resource.
     Possible values include: 'Succeeded', 'Updating', 'Deleting', 'Failed'
    :type provisioning_state: str or
     ~azure.mgmt.network.v2018_06_01.models.ProvisioningState
    :ivar etag: Gets a unique read-only string that changes whenever the
     resource is updated.
    :vartype etag: str
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'application_rule_collections': {'key': 'properties.applicationRuleCollections', 'type': '[AzureFirewallApplicationRuleCollection]'},
        'network_rule_collections': {'key': 'properties.networkRuleCollections', 'type': '[AzureFirewallNetworkRuleCollection]'},
        'ip_configurations': {'key': 'properties.ipConfigurations', 'type': '[AzureFirewallIPConfiguration]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, location: str=None, tags=None, application_rule_collections=None, network_rule_collections=None, ip_configurations=None, provisioning_state=None, **kwargs) -> None:
        super(AzureFirewall, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.application_rule_collections = application_rule_collections
        self.network_rule_collections = network_rule_collections
        self.ip_configurations = ip_configurations
        self.provisioning_state = provisioning_state
        self.etag = None
