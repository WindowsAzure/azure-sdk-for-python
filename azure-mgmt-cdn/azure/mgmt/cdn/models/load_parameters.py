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


class LoadParameters(Model):
    """Parameters required for content load.

    All required parameters must be populated in order to send to Azure.

    :param content_paths: Required. The path to the content to be loaded. Path
     should be a relative file URL of the origin.
    :type content_paths: list[str]
    """

    _validation = {
        'content_paths': {'required': True},
    }

    _attribute_map = {
        'content_paths': {'key': 'contentPaths', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(LoadParameters, self).__init__(**kwargs)
        self.content_paths = kwargs.get('content_paths', None)
