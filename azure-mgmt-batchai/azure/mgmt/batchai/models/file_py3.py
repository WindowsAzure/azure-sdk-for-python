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


class File(Model):
    """Properties of the file or directory.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Name. Name of the file.
    :vartype name: str
    :ivar file_type: File type. Type of the file. Possible values are file and
     directory. Possible values include: 'file', 'directory'
    :vartype file_type: str or ~azure.mgmt.batchai.models.FileType
    :ivar download_url: Download URL. URL to download the corresponding file.
     The downloadUrl is not returned for directories.
    :vartype download_url: str
    :ivar last_modified: Last modified time. The time at which the file was
     last modified.
    :vartype last_modified: datetime
    :ivar content_length: Content length. The file of the size.
    :vartype content_length: long
    """

    _validation = {
        'name': {'readonly': True},
        'file_type': {'readonly': True},
        'download_url': {'readonly': True},
        'last_modified': {'readonly': True},
        'content_length': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'file_type': {'key': 'fileType', 'type': 'str'},
        'download_url': {'key': 'downloadUrl', 'type': 'str'},
        'last_modified': {'key': 'properties.lastModified', 'type': 'iso-8601'},
        'content_length': {'key': 'properties.contentLength', 'type': 'long'},
    }

    def __init__(self, **kwargs) -> None:
        super(File, self).__init__(**kwargs)
        self.name = None
        self.file_type = None
        self.download_url = None
        self.last_modified = None
        self.content_length = None
