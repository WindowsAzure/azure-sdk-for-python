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


class FileDTO(Model):
    """DTO to hold details of uploaded files.

    All required parameters must be populated in order to send to Azure.

    :param file_name: Required. File name. Supported file types are ".tsv",
     ".pdf", ".txt", ".docx", ".xlsx".
    :type file_name: str
    :param file_uri: Required. Public URI of the file.
    :type file_uri: str
    """

    _validation = {
        'file_name': {'required': True, 'max_length': 200, 'min_length': 1},
        'file_uri': {'required': True},
    }

    _attribute_map = {
        'file_name': {'key': 'fileName', 'type': 'str'},
        'file_uri': {'key': 'fileUri', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(FileDTO, self).__init__(**kwargs)
        self.file_name = kwargs.get('file_name', None)
        self.file_uri = kwargs.get('file_uri', None)
