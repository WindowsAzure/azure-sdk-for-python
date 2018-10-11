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


class WebActivityAuthentication(Model):
    """Web activity authentication properties.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Web activity authentication
     (Basic/ClientCertificate/MSI)
    :type type: str
    :param pfx: Base64-encoded contents of a PFX file.
    :type pfx: ~azure.mgmt.datafactory.models.SecureString
    :param username: Web activity authentication user name for basic
     authentication.
    :type username: str
    :param password: Password for the PFX file or basic authentication.
    :type password: ~azure.mgmt.datafactory.models.SecureString
    :param resource: Resource for which Azure Auth token will be requested
     when using MSI Authentication.
    :type resource: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'pfx': {'key': 'pfx', 'type': 'SecureString'},
        'username': {'key': 'username', 'type': 'str'},
        'password': {'key': 'password', 'type': 'SecureString'},
        'resource': {'key': 'resource', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(WebActivityAuthentication, self).__init__(**kwargs)
        self.type = kwargs.get('type', None)
        self.pfx = kwargs.get('pfx', None)
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)
        self.resource = kwargs.get('resource', None)
