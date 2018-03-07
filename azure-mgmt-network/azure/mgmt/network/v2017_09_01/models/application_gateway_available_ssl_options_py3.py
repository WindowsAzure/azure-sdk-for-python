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


class ApplicationGatewayAvailableSslOptions(Resource):
    """Response for ApplicationGatewayAvailableSslOptions API service call.

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
    :param predefined_policies: List of available Ssl predefined policy.
    :type predefined_policies:
     list[~azure.mgmt.network.v2017_09_01.models.SubResource]
    :param default_policy: Name of the Ssl predefined policy applied by
     default to application gateway. Possible values include:
     'AppGwSslPolicy20150501', 'AppGwSslPolicy20170401',
     'AppGwSslPolicy20170401S'
    :type default_policy: str or
     ~azure.mgmt.network.v2017_09_01.models.ApplicationGatewaySslPolicyName
    :param available_cipher_suites: List of available Ssl cipher suites.
    :type available_cipher_suites: list[str or
     ~azure.mgmt.network.v2017_09_01.models.ApplicationGatewaySslCipherSuite]
    :param available_protocols: List of available Ssl protocols.
    :type available_protocols: list[str or
     ~azure.mgmt.network.v2017_09_01.models.ApplicationGatewaySslProtocol]
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'predefined_policies': {'key': 'properties.predefinedPolicies', 'type': '[SubResource]'},
        'default_policy': {'key': 'properties.defaultPolicy', 'type': 'str'},
        'available_cipher_suites': {'key': 'properties.availableCipherSuites', 'type': '[str]'},
        'available_protocols': {'key': 'properties.availableProtocols', 'type': '[str]'},
    }

    def __init__(self, *, id: str=None, location: str=None, tags=None, predefined_policies=None, default_policy=None, available_cipher_suites=None, available_protocols=None, **kwargs) -> None:
        super(ApplicationGatewayAvailableSslOptions, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.predefined_policies = predefined_policies
        self.default_policy = default_policy
        self.available_cipher_suites = available_cipher_suites
        self.available_protocols = available_protocols
