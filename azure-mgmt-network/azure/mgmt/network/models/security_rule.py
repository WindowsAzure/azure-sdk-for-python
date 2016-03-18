# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .sub_resource import SubResource


class SecurityRule(SubResource):
    """
    Network security rule

    :param id: Resource Id
    :type id: str
    :param description: Gets or sets a description for this rule. Restricted
     to 140 chars.
    :type description: str
    :param protocol: Gets or sets Network protocol this rule applies to. Can
     be Tcp, Udp or All(*). Possible values include: 'Tcp', 'Udp', '*'
    :type protocol: str
    :param source_port_range: Gets or sets Source Port or Range. Integer or
     range between 0 and 65535. Asterix '*' can also be used to match all
     ports.
    :type source_port_range: str
    :param destination_port_range: Gets or sets Destination Port or Range.
     Integer or range between 0 and 65535. Asterix '*' can also be used to
     match all ports.
    :type destination_port_range: str
    :param source_address_prefix: Gets or sets source address prefix. CIDR or
     source IP range. Asterix '*' can also be used to match all source IPs.
     Default tags such as 'VirtualNetwork', 'AzureLoadBalancer' and
     'Internet' can also be used. If this is an ingress rule, specifies where
     network traffic originates from.
    :type source_address_prefix: str
    :param destination_address_prefix: Gets or sets destination address
     prefix. CIDR or source IP range. Asterix '*' can also be used to match
     all source IPs. Default tags such as 'VirtualNetwork',
     'AzureLoadBalancer' and 'Internet' can also be used.
    :type destination_address_prefix: str
    :param access: Gets or sets network traffic is allowed or denied.
     Possible values are 'Allow' and 'Deny'. Possible values include:
     'Allow', 'Deny'
    :type access: str
    :param priority: Gets or sets the priority of the rule. The value can be
     between 100 and 4096. The priority number must be unique for each rule
     in the collection. The lower the priority number, the higher the
     priority of the rule.
    :type priority: int
    :param direction: Gets or sets the direction of the rule.InBound or
     Outbound. The direction specifies if rule will be evaluated on incoming
     or outcoming traffic. Possible values include: 'Inbound', 'Outbound'
    :type direction: str
    :param provisioning_state: Gets or sets Provisioning state of the
     PublicIP resource Updating/Deleting/Failed
    :type provisioning_state: str
    :param name: Gets name of the resource that is unique within a resource
     group. This name can be used to access the resource
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated
    :type etag: str
    """ 

    _validation = {
        'protocol': {'required': True},
        'source_address_prefix': {'required': True},
        'destination_address_prefix': {'required': True},
        'access': {'required': True},
        'direction': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'protocol': {'key': 'properties.protocol', 'type': 'SecurityRuleProtocol'},
        'source_port_range': {'key': 'properties.sourcePortRange', 'type': 'str'},
        'destination_port_range': {'key': 'properties.destinationPortRange', 'type': 'str'},
        'source_address_prefix': {'key': 'properties.sourceAddressPrefix', 'type': 'str'},
        'destination_address_prefix': {'key': 'properties.destinationAddressPrefix', 'type': 'str'},
        'access': {'key': 'properties.access', 'type': 'SecurityRuleAccess'},
        'priority': {'key': 'properties.priority', 'type': 'int'},
        'direction': {'key': 'properties.direction', 'type': 'SecurityRuleDirection'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, protocol, source_address_prefix, destination_address_prefix, access, direction, id=None, description=None, source_port_range=None, destination_port_range=None, priority=None, provisioning_state=None, name=None, etag=None, **kwargs):
        super(SecurityRule, self).__init__(id=id, **kwargs)
        self.description = description
        self.protocol = protocol
        self.source_port_range = source_port_range
        self.destination_port_range = destination_port_range
        self.source_address_prefix = source_address_prefix
        self.destination_address_prefix = destination_address_prefix
        self.access = access
        self.priority = priority
        self.direction = direction
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
