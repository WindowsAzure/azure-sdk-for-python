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


class BlobShare(Model):
    """Blob container storage information.

    All required parameters must be populated in order to send to Azure.

    :param sas_uri: Required. SAS URI of Azure Storage Account Container.
    :type sas_uri: str
    """

    _validation = {
        'sas_uri': {'required': True},
    }

    _attribute_map = {
        'sas_uri': {'key': 'sasUri', 'type': 'str'},
    }

    def __init__(self, *, sas_uri: str, **kwargs) -> None:
        super(BlobShare, self).__init__(**kwargs)
        self.sas_uri = sas_uri
