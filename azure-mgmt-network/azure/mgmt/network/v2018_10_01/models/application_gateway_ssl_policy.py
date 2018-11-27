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


class ApplicationGatewaySslPolicy(Model):
    """Application Gateway Ssl policy.

    :param disabled_ssl_protocols: Ssl protocols to be disabled on application
     gateway.
    :type disabled_ssl_protocols: list[str or
     ~azure.mgmt.network.v2018_10_01.models.ApplicationGatewaySslProtocol]
    :param policy_type: Type of Ssl Policy. Possible values include:
     'Predefined', 'Custom'
    :type policy_type: str or
     ~azure.mgmt.network.v2018_10_01.models.ApplicationGatewaySslPolicyType
    :param policy_name: Name of Ssl predefined policy. Possible values
     include: 'AppGwSslPolicy20150501', 'AppGwSslPolicy20170401',
     'AppGwSslPolicy20170401S'
    :type policy_name: str or
     ~azure.mgmt.network.v2018_10_01.models.ApplicationGatewaySslPolicyName
    :param cipher_suites: Ssl cipher suites to be enabled in the specified
     order to application gateway.
    :type cipher_suites: list[str or
     ~azure.mgmt.network.v2018_10_01.models.ApplicationGatewaySslCipherSuite]
    :param min_protocol_version: Minimum version of Ssl protocol to be
     supported on application gateway. Possible values include: 'TLSv1_0',
     'TLSv1_1', 'TLSv1_2'
    :type min_protocol_version: str or
     ~azure.mgmt.network.v2018_10_01.models.ApplicationGatewaySslProtocol
    """

    _attribute_map = {
        'disabled_ssl_protocols': {'key': 'disabledSslProtocols', 'type': '[str]'},
        'policy_type': {'key': 'policyType', 'type': 'str'},
        'policy_name': {'key': 'policyName', 'type': 'str'},
        'cipher_suites': {'key': 'cipherSuites', 'type': '[str]'},
        'min_protocol_version': {'key': 'minProtocolVersion', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ApplicationGatewaySslPolicy, self).__init__(**kwargs)
        self.disabled_ssl_protocols = kwargs.get('disabled_ssl_protocols', None)
        self.policy_type = kwargs.get('policy_type', None)
        self.policy_name = kwargs.get('policy_name', None)
        self.cipher_suites = kwargs.get('cipher_suites', None)
        self.min_protocol_version = kwargs.get('min_protocol_version', None)
