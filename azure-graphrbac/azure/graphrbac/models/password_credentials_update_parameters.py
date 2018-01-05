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


class PasswordCredentialsUpdateParameters(Model):
    """Request parameters for a PasswordCredentials update operation.

    :param value: A collection of PasswordCredentials.
    :type value: list[~azure.graphrbac.models.PasswordCredential]
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[PasswordCredential]'},
    }

    def __init__(self, value):
        super(PasswordCredentialsUpdateParameters, self).__init__()
        self.value = value
