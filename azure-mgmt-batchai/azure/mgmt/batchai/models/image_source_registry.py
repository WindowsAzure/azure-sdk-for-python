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


class ImageSourceRegistry(Model):
    """Details of the container image such as name, URL and credentials.

    All required parameters must be populated in order to send to Azure.

    :param server_url: URL for image repository.
    :type server_url: str
    :param image: Required. The name of the image in image repository.
    :type image: str
    :param credentials: Information to access the private Docker repository.
    :type credentials: ~azure.mgmt.batchai.models.PrivateRegistryCredentials
    """

    _validation = {
        'image': {'required': True},
    }

    _attribute_map = {
        'server_url': {'key': 'serverUrl', 'type': 'str'},
        'image': {'key': 'image', 'type': 'str'},
        'credentials': {'key': 'credentials', 'type': 'PrivateRegistryCredentials'},
    }

    def __init__(self, **kwargs):
        super(ImageSourceRegistry, self).__init__(**kwargs)
        self.server_url = kwargs.get('server_url', None)
        self.image = kwargs.get('image', None)
        self.credentials = kwargs.get('credentials', None)
