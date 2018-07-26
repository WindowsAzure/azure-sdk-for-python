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


class RestoreFileSpecs(Model):
    """Restore file specs like file path, type and target folder path info.

    :param path: Source File/Folder path
    :type path: str
    :param file_spec_type: Indicates what the Path variable stands for
    :type file_spec_type: str
    :param target_folder_path: Destination folder path in target FileShare
    :type target_folder_path: str
    """

    _attribute_map = {
        'path': {'key': 'path', 'type': 'str'},
        'file_spec_type': {'key': 'fileSpecType', 'type': 'str'},
        'target_folder_path': {'key': 'targetFolderPath', 'type': 'str'},
    }

    def __init__(self, *, path: str=None, file_spec_type: str=None, target_folder_path: str=None, **kwargs) -> None:
        super(RestoreFileSpecs, self).__init__(**kwargs)
        self.path = path
        self.file_spec_type = file_spec_type
        self.target_folder_path = target_folder_path
