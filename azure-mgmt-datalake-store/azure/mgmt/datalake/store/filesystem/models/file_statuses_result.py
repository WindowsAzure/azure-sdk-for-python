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


class FileStatusesResult(Model):
    """Data Lake Store filesystem file status list information response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar file_statuses: the object representing the list of file statuses.
    :vartype file_statuses: :class:`FileStatuses
     <azure.mgmt.datalake.store.filesystem.models.FileStatuses>`
    """ 

    _validation = {
        'file_statuses': {'readonly': True},
    }

    _attribute_map = {
        'file_statuses': {'key': 'FileStatuses', 'type': 'FileStatuses'},
    }

    def __init__(self):
        self.file_statuses = None
