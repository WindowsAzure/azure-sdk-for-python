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


class TopLevelDomain(ProxyOnlyResource):
    """A top level domain object.

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
    :ivar domain_name: Name of the top level domain.
    :vartype domain_name: str
    :param privacy: If <code>true</code>, then the top level domain supports
     domain privacy; otherwise, <code>false</code>.
    :type privacy: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'domain_name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'domain_name': {'key': 'properties.name', 'type': 'str'},
        'privacy': {'key': 'properties.privacy', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(TopLevelDomain, self).__init__(**kwargs)
        self.domain_name = None
        self.privacy = kwargs.get('privacy', None)
