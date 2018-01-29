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


class AadMetadataObject(Model):
    """Azure Active Directory metadata object used for secured connection to
    cluster.

    :param type: The client authentication method.
    :type type: str
    :param metadata:
    :type metadata: ~azure.servicefabric.models.AadMetadata
    """

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'metadata': {'key': 'metadata', 'type': 'AadMetadata'},
    }

    def __init__(self, type=None, metadata=None):
        super(AadMetadataObject, self).__init__()
        self.type = type
        self.metadata = metadata
