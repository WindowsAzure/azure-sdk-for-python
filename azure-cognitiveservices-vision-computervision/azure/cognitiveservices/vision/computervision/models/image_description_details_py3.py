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


class ImageDescriptionDetails(Model):
    """A collection of content tags, along with a list of captions sorted by
    confidence level, and image metadata.

    :param tags: A collection of image tags.
    :type tags: list[str]
    :param captions: A list of captions, sorted by confidence level.
    :type captions:
     list[~azure.cognitiveservices.vision.computervision.models.ImageCaption]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '[str]'},
        'captions': {'key': 'captions', 'type': '[ImageCaption]'},
    }

    def __init__(self, *, tags=None, captions=None, **kwargs) -> None:
        super(ImageDescriptionDetails, self).__init__(**kwargs)
        self.tags = tags
        self.captions = captions
