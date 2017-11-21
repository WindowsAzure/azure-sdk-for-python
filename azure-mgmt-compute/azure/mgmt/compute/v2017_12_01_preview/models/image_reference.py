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

from .sub_resource import SubResource


class ImageReference(SubResource):
    """Specifies information about the image to use. You can specify information
    about platform images, marketplace images, or virtual machine images. This
    element is required when you want to use a platform image, marketplace
    image, or virtual machine image, but is not used in other creation
    operations.

    :param id: Resource Id
    :type id: str
    :param publisher: The image publisher.
    :type publisher: str
    :param offer: Specifies the offer of the platform image or marketplace
     image used to create the virtual machine.
    :type offer: str
    :param sku: The image SKU.
    :type sku: str
    :param version: Specifies the version of the platform image or marketplace
     image used to create the virtual machine. The allowed formats are
     Major.Minor.Build or 'latest'. Major, Minor, and Build are decimal
     numbers. Specify 'latest' to use the latest version of an image available
     at deploy time. Even if you use 'latest', the VM image will not
     automatically update after deploy time even if a new version becomes
     available.
    :type version: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'publisher': {'key': 'publisher', 'type': 'str'},
        'offer': {'key': 'offer', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'str'},
        'version': {'key': 'version', 'type': 'str'},
    }

    def __init__(self, id=None, publisher=None, offer=None, sku=None, version=None):
        super(ImageReference, self).__init__(id=id)
        self.publisher = publisher
        self.offer = offer
        self.sku = sku
        self.version = version
