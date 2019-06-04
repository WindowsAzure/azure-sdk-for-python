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

from .tracked_resource import TrackedResource


class Account(TrackedResource):
    """The EngagementFabric account.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The ID of the resource
    :vartype id: str
    :ivar name: The name of the resource
    :vartype name: str
    :ivar type: The fully qualified type of the resource
    :vartype type: str
    :param location: Required. The location of the resource
    :type location: str
    :param tags: The tags of the resource
    :type tags: dict[str, str]
    :param sku: Required. The SKU of the resource
    :type sku: ~azure.mgmt.engagementfabric.models.SKU
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'sku': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'SKU'},
    }

    def __init__(self, **kwargs):
        super(Account, self).__init__(**kwargs)
