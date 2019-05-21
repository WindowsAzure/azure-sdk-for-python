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


class UpdateSnapshotRequest(Model):
    """Request body for updating a snapshot, with a combination of user defined
    apply scope and user specified data.

    :param apply_scope: Array of the target Face subscription ids for the
     snapshot, specified by the user who created the snapshot when calling
     Snapshot - Take. For each snapshot, only subscriptions included in the
     applyScope of Snapshot - Take can apply it.
    :type apply_scope: list[str]
    :param user_data: User specified data about the snapshot for any purpose.
     Length should not exceed 16KB.
    :type user_data: str
    """

    _validation = {
        'user_data': {'max_length': 16384},
    }

    _attribute_map = {
        'apply_scope': {'key': 'applyScope', 'type': '[str]'},
        'user_data': {'key': 'userData', 'type': 'str'},
    }

    def __init__(self, *, apply_scope=None, user_data: str=None, **kwargs) -> None:
        super(UpdateSnapshotRequest, self).__init__(**kwargs)
        self.apply_scope = apply_scope
        self.user_data = user_data
