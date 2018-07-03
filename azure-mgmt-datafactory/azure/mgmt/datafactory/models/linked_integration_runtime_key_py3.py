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

from .linked_integration_runtime_properties_py3 import LinkedIntegrationRuntimeProperties


class LinkedIntegrationRuntimeKey(LinkedIntegrationRuntimeProperties):
    """The key authorization type.

    All required parameters must be populated in order to send to Azure.

    :param authorization_type: Required. Constant filled by server.
    :type authorization_type: str
    :param key: Required. The key used for authorization.
    :type key: ~azure.mgmt.datafactory.models.SecureString
    """

    _validation = {
        'authorization_type': {'required': True},
        'key': {'required': True},
    }

    _attribute_map = {
        'authorization_type': {'key': 'authorizationType', 'type': 'str'},
        'key': {'key': 'key', 'type': 'SecureString'},
    }

    def __init__(self, *, key, **kwargs) -> None:
        super(LinkedIntegrationRuntimeKey, self).__init__(**kwargs)
        self.key = key
        self.authorization_type = 'Key'
