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

from .image_template_source import ImageTemplateSource


class ImageTemplatePlatformImageSource(ImageTemplateSource):
    """Describes an image source from [Azure Gallery
    Images](https://docs.microsoft.com/en-us/rest/api/compute/virtualmachineimages).

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Constant filled by server.
    :type type: str
    :param publisher: Image Publisher in [Azure Gallery
     Images](https://docs.microsoft.com/en-us/rest/api/compute/virtualmachineimages).
    :type publisher: str
    :param offer: Image offer from the [Azure Gallery
     Images](https://docs.microsoft.com/en-us/rest/api/compute/virtualmachineimages).
    :type offer: str
    :param sku: Image sku from the [Azure Gallery
     Images](https://docs.microsoft.com/en-us/rest/api/compute/virtualmachineimages).
    :type sku: str
    :param version: Image version from the [Azure Gallery
     Images](https://docs.microsoft.com/en-us/rest/api/compute/virtualmachineimages).
    :type version: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'publisher': {'key': 'publisher', 'type': 'str'},
        'offer': {'key': 'offer', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ImageTemplatePlatformImageSource, self).__init__(**kwargs)
        self.publisher = kwargs.get('publisher', None)
        self.offer = kwargs.get('offer', None)
        self.sku = kwargs.get('sku', None)
        self.version = kwargs.get('version', None)
        self.type = 'PlatformImage'
