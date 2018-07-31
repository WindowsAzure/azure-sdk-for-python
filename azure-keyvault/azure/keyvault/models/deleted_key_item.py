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

from .key_item import KeyItem


class DeletedKeyItem(KeyItem):
    """The deleted key item containing the deleted key metadata and information
    about deletion.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param kid: Key identifier.
    :type kid: str
    :param attributes: The key management attributes.
    :type attributes: ~azure.keyvault.models.KeyAttributes
    :param tags: Application specific metadata in the form of key-value pairs.
    :type tags: dict[str, str]
    :ivar managed: True if the key's lifetime is managed by key vault. If this
     is a key backing a certificate, then managed will be true.
    :vartype managed: bool
    :param recovery_id: The url of the recovery object, used to identify and
     recover the deleted key.
    :type recovery_id: str
    :ivar scheduled_purge_date: The time when the key is scheduled to be
     purged, in UTC
    :vartype scheduled_purge_date: datetime
    :ivar deleted_date: The time when the key was deleted, in UTC
    :vartype deleted_date: datetime
    """

    _validation = {
        'managed': {'readonly': True},
        'scheduled_purge_date': {'readonly': True},
        'deleted_date': {'readonly': True},
    }

    _attribute_map = {
        'kid': {'key': 'kid', 'type': 'str'},
        'attributes': {'key': 'attributes', 'type': 'KeyAttributes'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'managed': {'key': 'managed', 'type': 'bool'},
        'recovery_id': {'key': 'recoveryId', 'type': 'str'},
        'scheduled_purge_date': {'key': 'scheduledPurgeDate', 'type': 'unix-time'},
        'deleted_date': {'key': 'deletedDate', 'type': 'unix-time'},
    }

    def __init__(self, **kwargs):
        super(DeletedKeyItem, self).__init__(**kwargs)
        self.recovery_id = kwargs.get('recovery_id', None)
        self.scheduled_purge_date = None
        self.deleted_date = None
