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

from .route_configuration import RouteConfiguration


class ForwardingConfiguration(RouteConfiguration):
    """Describes Forwarding Route.

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param custom_forwarding_path: A custom path used to rewrite resource
     paths matched by this rule. Leave empty to use incoming path.
    :type custom_forwarding_path: str
    :param forwarding_protocol: Protocol this rule will use when forwarding
     traffic to backends. Possible values include: 'HttpOnly', 'HttpsOnly',
     'MatchRequest'
    :type forwarding_protocol: str or
     ~azure.mgmt.frontdoor.models.FrontDoorForwardingProtocol
    :param cache_configuration: The caching configuration associated with this
     rule.
    :type cache_configuration: ~azure.mgmt.frontdoor.models.CacheConfiguration
    :param backend_pool: A reference to the BackendPool which this rule routes
     to.
    :type backend_pool: ~azure.mgmt.frontdoor.models.SubResource
    """

    _validation = {
        'odatatype': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'custom_forwarding_path': {'key': 'customForwardingPath', 'type': 'str'},
        'forwarding_protocol': {'key': 'forwardingProtocol', 'type': 'str'},
        'cache_configuration': {'key': 'cacheConfiguration', 'type': 'CacheConfiguration'},
        'backend_pool': {'key': 'backendPool', 'type': 'SubResource'},
    }

    def __init__(self, **kwargs):
        super(ForwardingConfiguration, self).__init__(**kwargs)
        self.custom_forwarding_path = kwargs.get('custom_forwarding_path', None)
        self.forwarding_protocol = kwargs.get('forwarding_protocol', None)
        self.cache_configuration = kwargs.get('cache_configuration', None)
        self.backend_pool = kwargs.get('backend_pool', None)
        self.odatatype = '#Microsoft.Azure.FrontDoor.Models.FrontdoorForwardingConfiguration'
