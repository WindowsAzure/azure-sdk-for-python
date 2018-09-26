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

from .dataset_compression_py3 import DatasetCompression


class DatasetZipDeflateCompression(DatasetCompression):
    """The ZipDeflate compression method used on a dataset.

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param type: Required. Constant filled by server.
    :type type: str
    :param level: The ZipDeflate compression level. Possible values include:
     'Optimal', 'Fastest'
    :type level: str or ~azure.mgmt.datafactory.models.DatasetCompressionLevel
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'type': {'key': 'type', 'type': 'str'},
        'level': {'key': 'level', 'type': 'str'},
    }

    def __init__(self, *, additional_properties=None, level=None, **kwargs) -> None:
        super(DatasetZipDeflateCompression, self).__init__(additional_properties=additional_properties, **kwargs)
        self.level = level
        self.type = 'ZipDeflate'
