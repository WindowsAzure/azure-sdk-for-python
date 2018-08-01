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

from .proxy_resource_py3 import ProxyResource


class TagsResult(ProxyResource):
    """A resource listing all tags.

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
    :param tags: A list of Tag.
    :type tags: list[~azure.mgmt.consumption.models.Tag]
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
        'tags': {'key': 'properties.tags', 'type': '[Tag]'},
    }

    def __init__(self, *, e_tag: str=None, tags=None, **kwargs) -> None:
        super(TagsResult, self).__init__(e_tag=e_tag, **kwargs)
        self.tags = tags
