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


class ProjectFileProperties(Model):
    """Base class for file properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param extension: Optional File extension. If submitted it should not have
     a leading period and must match the extension from filePath.
    :type extension: str
    :param file_path: Relative path of this file resource. This property can
     be set when creating or updating the file resource.
    :type file_path: str
    :ivar last_modified: Modification DateTime.
    :vartype last_modified: datetime
    :param media_type: File content type. This property can be modified to
     reflect the file content type.
    :type media_type: str
    :ivar size: File size.
    :vartype size: long
    """

    _validation = {
        'last_modified': {'readonly': True},
        'size': {'readonly': True},
    }

    _attribute_map = {
        'extension': {'key': 'extension', 'type': 'str'},
        'file_path': {'key': 'filePath', 'type': 'str'},
        'last_modified': {'key': 'lastModified', 'type': 'iso-8601'},
        'media_type': {'key': 'mediaType', 'type': 'str'},
        'size': {'key': 'size', 'type': 'long'},
    }

    def __init__(self, *, extension: str=None, file_path: str=None, media_type: str=None, **kwargs) -> None:
        super(ProjectFileProperties, self).__init__(**kwargs)
        self.extension = extension
        self.file_path = file_path
        self.last_modified = None
        self.media_type = media_type
        self.size = None
