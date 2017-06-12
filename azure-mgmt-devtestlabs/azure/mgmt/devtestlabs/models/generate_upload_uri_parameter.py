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


class GenerateUploadUriParameter(Model):
    """Properties for generating an upload URI.

    :param blob_name: The blob name of the upload URI.
    :type blob_name: str
    """ 

    _attribute_map = {
        'blob_name': {'key': 'blobName', 'type': 'str'},
    }

    def __init__(self, blob_name=None):
        self.blob_name = blob_name
