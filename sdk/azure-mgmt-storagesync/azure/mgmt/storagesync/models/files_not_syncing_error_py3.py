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


class FilesNotSyncingError(Model):
    """Files not syncing error object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar error_code: Error code (HResult)
    :vartype error_code: int
    :ivar persistent_count: Count of persistent files not syncing with the
     specified error code
    :vartype persistent_count: long
    :ivar transient_count: Count of transient files not syncing with the
     specified error code
    :vartype transient_count: long
    """

    _validation = {
        'error_code': {'readonly': True},
        'persistent_count': {'readonly': True},
        'transient_count': {'readonly': True},
    }

    _attribute_map = {
        'error_code': {'key': 'errorCode', 'type': 'int'},
        'persistent_count': {'key': 'persistentCount', 'type': 'long'},
        'transient_count': {'key': 'transientCount', 'type': 'long'},
    }

    def __init__(self, **kwargs) -> None:
        super(FilesNotSyncingError, self).__init__(**kwargs)
        self.error_code = None
        self.persistent_count = None
        self.transient_count = None
