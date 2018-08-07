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


class ParametersLink(Model):
    """Entity representing the reference to the deployment paramaters.

    All required parameters must be populated in order to send to Azure.

    :param uri: Required. The URI of the parameters file.
    :type uri: str
    :param content_version: If included, must match the ContentVersion in the
     template.
    :type content_version: str
    """

    _validation = {
        'uri': {'required': True},
    }

    _attribute_map = {
        'uri': {'key': 'uri', 'type': 'str'},
        'content_version': {'key': 'contentVersion', 'type': 'str'},
    }

    def __init__(self, *, uri: str, content_version: str=None, **kwargs) -> None:
        super(ParametersLink, self).__init__(**kwargs)
        self.uri = uri
        self.content_version = content_version
