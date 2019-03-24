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


class CustomAlertRule(Model):
    """A custom alert rule.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar display_name: The display name of the custom alert.
    :vartype display_name: str
    :ivar description: The description of the custom alert.
    :vartype description: str
    :param is_enabled: Required. Whether the custom alert is enabled.
    :type is_enabled: bool
    :param rule_type: Required. The type of the custom alert rule.
    :type rule_type: str
    """

    _validation = {
        'display_name': {'readonly': True},
        'description': {'readonly': True},
        'is_enabled': {'required': True},
        'rule_type': {'required': True},
    }

    _attribute_map = {
        'display_name': {'key': 'displayName', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'is_enabled': {'key': 'isEnabled', 'type': 'bool'},
        'rule_type': {'key': 'ruleType', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(CustomAlertRule, self).__init__(**kwargs)
        self.display_name = None
        self.description = None
        self.is_enabled = kwargs.get('is_enabled', None)
        self.rule_type = kwargs.get('rule_type', None)
