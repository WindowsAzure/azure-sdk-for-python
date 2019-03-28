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


class ImageUrlCreateEntry(Model):
    """ImageUrlCreateEntry.

    All required parameters must be populated in order to send to Azure.

    :param url: Required. Url of the image.
    :type url: str
    :param tag_ids:
    :type tag_ids: list[str]
    :param regions:
    :type regions:
     list[~azure.cognitiveservices.vision.customvision.training.models.Region]
    """

    _validation = {
        'url': {'required': True},
    }

    _attribute_map = {
        'url': {'key': 'url', 'type': 'str'},
        'tag_ids': {'key': 'tagIds', 'type': '[str]'},
        'regions': {'key': 'regions', 'type': '[Region]'},
    }

    def __init__(self, *, url: str, tag_ids=None, regions=None, **kwargs) -> None:
        super(ImageUrlCreateEntry, self).__init__(**kwargs)
        self.url = url
        self.tag_ids = tag_ids
        self.regions = regions
