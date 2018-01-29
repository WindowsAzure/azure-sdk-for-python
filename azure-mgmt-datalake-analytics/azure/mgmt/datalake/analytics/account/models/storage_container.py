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


class StorageContainer(Model):
    """Azure Storage blob container information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The unique identifier of the blob container.
    :vartype id: str
    :ivar name: The name of the blob container.
    :vartype name: str
    :ivar type: The type of the blob container.
    :vartype type: str
    :ivar last_modified_time: The last modified time of the blob container.
    :vartype last_modified_time: datetime
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'last_modified_time': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'last_modified_time': {'key': 'properties.lastModifiedTime', 'type': 'iso-8601'},
    }

    def __init__(self):
        super(StorageContainer, self).__init__()
        self.id = None
        self.name = None
        self.type = None
        self.last_modified_time = None
