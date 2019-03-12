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


class ProxyResource(Model):
    """The Resource model definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param e_tag: eTag of the resource. To handle concurrent update scenarion,
     this field will be used to determine whether the user is updating the
     latest version or not.
    :type e_tag: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'e_tag': {'key': 'eTag', 'type': 'str'},
    }

    def __init__(self, e_tag=None):
        super(ProxyResource, self).__init__()
        self.id = None
        self.name = None
        self.type = None
        self.e_tag = e_tag
