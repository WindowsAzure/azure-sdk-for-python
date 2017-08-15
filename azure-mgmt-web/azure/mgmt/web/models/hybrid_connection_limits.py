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

from .proxy_only_resource import ProxyOnlyResource


class HybridConnectionLimits(ProxyOnlyResource):
    """Hybrid Connection limits contract. This is used to return the plan limits
    of Hybrid Connections.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar current: The current number of Hybrid Connections.
    :vartype current: int
    :ivar maximum: The maximum number of Hybrid Connections allowed.
    :vartype maximum: int
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'current': {'readonly': True},
        'maximum': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'current': {'key': 'properties.current', 'type': 'int'},
        'maximum': {'key': 'properties.maximum', 'type': 'int'},
    }

    def __init__(self, kind=None):
        super(HybridConnectionLimits, self).__init__(kind=kind)
        self.current = None
        self.maximum = None
