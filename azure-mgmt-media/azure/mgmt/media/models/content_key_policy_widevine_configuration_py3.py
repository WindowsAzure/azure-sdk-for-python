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

from .content_key_policy_configuration import ContentKeyPolicyConfiguration


class ContentKeyPolicyWidevineConfiguration(ContentKeyPolicyConfiguration):
    """Specifies a configuration for Widevine licenses.

    All required parameters must be populated in order to send to Azure.

    :param odatatype: Required. Constant filled by server.
    :type odatatype: str
    :param widevine_template: Required. The Widevine template.
    :type widevine_template: str
    """

    _validation = {
        'odatatype': {'required': True},
        'widevine_template': {'required': True},
    }

    _attribute_map = {
        'odatatype': {'key': '@odata\\.type', 'type': 'str'},
        'widevine_template': {'key': 'widevineTemplate', 'type': 'str'},
    }

    def __init__(self, *, widevine_template: str, **kwargs) -> None:
        super(ContentKeyPolicyWidevineConfiguration, self).__init__(, **kwargs)
        self.widevine_template = widevine_template
        self.odatatype = '#Microsoft.Media.ContentKeyPolicyWidevineConfiguration'
