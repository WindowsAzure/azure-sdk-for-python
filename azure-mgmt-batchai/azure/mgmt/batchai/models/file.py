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

    :param name: Name of the file.
    :type name: str
    :param is_directory: Indicates if the file is a directory.
    :type is_directory: bool
    :param download_url: Will contain an URL to download the corresponding
     file. The downloadUrl is not returned for directories.
    :type download_url: str
    :param last_modified: The time at which the file was last modified. The
     time at which the file was last modified.
    :type last_modified: datetime
    :param content_length: The file size. The file size.
    :type content_length: long
    """

    _validation = {
        'name': {'required': True},
        'is_directory': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'is_directory': {'key': 'isDirectory', 'type': 'bool'},
        'download_url': {'key': 'downloadUrl', 'type': 'str'},
        'last_modified': {'key': 'properties.lastModified', 'type': 'iso-8601'},
        'content_length': {'key': 'properties.contentLength', 'type': 'long'},
    }

    def __init__(self, name, is_directory, download_url=None, last_modified=None, content_length=None):
        super(File, self).__init__()
        self.name = name
        self.is_directory = is_directory
        self.download_url = download_url
        self.last_modified = last_modified
        self.content_length = content_length
