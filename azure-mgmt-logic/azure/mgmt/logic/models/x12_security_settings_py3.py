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


class X12SecuritySettings(Model):
    """The X12 agreement security settings.

    All required parameters must be populated in order to send to Azure.

    :param authorization_qualifier: Required. The authorization qualifier.
    :type authorization_qualifier: str
    :param authorization_value: The authorization value.
    :type authorization_value: str
    :param security_qualifier: Required. The security qualifier.
    :type security_qualifier: str
    :param password_value: The password value.
    :type password_value: str
    """

    _validation = {
        'authorization_qualifier': {'required': True},
        'security_qualifier': {'required': True},
    }

    _attribute_map = {
        'authorization_qualifier': {'key': 'authorizationQualifier', 'type': 'str'},
        'authorization_value': {'key': 'authorizationValue', 'type': 'str'},
        'security_qualifier': {'key': 'securityQualifier', 'type': 'str'},
        'password_value': {'key': 'passwordValue', 'type': 'str'},
    }

    def __init__(self, *, authorization_qualifier: str, security_qualifier: str, authorization_value: str=None, password_value: str=None, **kwargs) -> None:
        super(X12SecuritySettings, self).__init__(**kwargs)
        self.authorization_qualifier = authorization_qualifier
        self.authorization_value = authorization_value
        self.security_qualifier = security_qualifier
        self.password_value = password_value
