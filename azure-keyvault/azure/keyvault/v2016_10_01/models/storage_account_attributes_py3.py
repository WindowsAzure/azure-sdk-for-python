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


class StorageAccountAttributes(Model):
    """The storage account management attributes.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param enabled: the enabled state of the object.
    :type enabled: bool
    :ivar created: Creation time in UTC.
    :vartype created: datetime
    :ivar updated: Last updated time in UTC.
    :vartype updated: datetime
    """

    _validation = {
        'created': {'readonly': True},
        'updated': {'readonly': True},
    }

    _attribute_map = {
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'created': {'key': 'created', 'type': 'unix-time'},
        'updated': {'key': 'updated', 'type': 'unix-time'},
    }

    def __init__(self, *, enabled: bool=None, **kwargs) -> None:
        super(StorageAccountAttributes, self).__init__(**kwargs)
        self.enabled = enabled
        self.created = None
        self.updated = None
