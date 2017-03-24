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


class ContainerServiceServicePrincipalProfile(Model):
    """Information about a service principal identity for the cluster to use for
    manipulating Azure APIs.

    :param client_id: The ID for the service principal.
    :type client_id: str
    :param secret: The secret password associated with the service principal.
    :type secret: str
    """

    _validation = {
        'client_id': {'required': True},
        'secret': {'required': True},
    }

    _attribute_map = {
        'client_id': {'key': 'clientId', 'type': 'str'},
        'secret': {'key': 'secret', 'type': 'str'},
    }

    def __init__(self, client_id, secret):
        self.client_id = client_id
        self.secret = secret
