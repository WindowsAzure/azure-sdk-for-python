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


class DeletedVaultProperties(Model):
    """Properties of the deleted vault.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar vault_id: The resource id of the original vault.
    :vartype vault_id: str
    :ivar location: The location of the original vault.
    :vartype location: str
    :ivar deletion_date: The deleted date.
    :vartype deletion_date: datetime
    :ivar scheduled_purge_date: The scheduled purged date.
    :vartype scheduled_purge_date: datetime
    :ivar tags: Tags of the original vault.
    :vartype tags: dict[str, str]
    """

    _validation = {
        'vault_id': {'readonly': True},
        'location': {'readonly': True},
        'deletion_date': {'readonly': True},
        'scheduled_purge_date': {'readonly': True},
        'tags': {'readonly': True},
    }

    _attribute_map = {
        'vault_id': {'key': 'vaultId', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'deletion_date': {'key': 'deletionDate', 'type': 'iso-8601'},
        'scheduled_purge_date': {'key': 'scheduledPurgeDate', 'type': 'iso-8601'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self):
        super(DeletedVaultProperties, self).__init__()
        self.vault_id = None
        self.location = None
        self.deletion_date = None
        self.scheduled_purge_date = None
        self.tags = None
