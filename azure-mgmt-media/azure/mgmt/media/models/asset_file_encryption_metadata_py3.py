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


class AssetFileEncryptionMetadata(Model):
    """The Asset File Storage encryption metadata.

    All required parameters must be populated in order to send to Azure.

    :param initialization_vector: The Asset File initialization vector.
    :type initialization_vector: str
    :param asset_file_name: The Asset File name.
    :type asset_file_name: str
    :param asset_file_id: Required. The Asset File Id.
    :type asset_file_id: str
    """

    _validation = {
        'asset_file_id': {'required': True},
    }

    _attribute_map = {
        'initialization_vector': {'key': 'initializationVector', 'type': 'str'},
        'asset_file_name': {'key': 'assetFileName', 'type': 'str'},
        'asset_file_id': {'key': 'assetFileId', 'type': 'str'},
    }

    def __init__(self, *, asset_file_id: str, initialization_vector: str=None, asset_file_name: str=None, **kwargs) -> None:
        super(AssetFileEncryptionMetadata, self).__init__(**kwargs)
        self.initialization_vector = initialization_vector
        self.asset_file_name = asset_file_name
        self.asset_file_id = asset_file_id
