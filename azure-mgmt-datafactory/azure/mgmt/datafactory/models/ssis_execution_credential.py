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


class SSISExecutionCredential(Model):
    """SSIS package execution credential.

    All required parameters must be populated in order to send to Azure.

    :param domain: Required. Domain for windows authentication.
    :type domain: object
    :param user_name: Required. UseName for windows authentication.
    :type user_name: object
    :param password: Required. Password for windows authentication.
    :type password: ~azure.mgmt.datafactory.models.SecureString
    """

    _validation = {
        'domain': {'required': True},
        'user_name': {'required': True},
        'password': {'required': True},
    }

    _attribute_map = {
        'domain': {'key': 'domain', 'type': 'object'},
        'user_name': {'key': 'userName', 'type': 'object'},
        'password': {'key': 'password', 'type': 'SecureString'},
    }

    def __init__(self, **kwargs):
        super(SSISExecutionCredential, self).__init__(**kwargs)
        self.domain = kwargs.get('domain', None)
        self.user_name = kwargs.get('user_name', None)
        self.password = kwargs.get('password', None)
