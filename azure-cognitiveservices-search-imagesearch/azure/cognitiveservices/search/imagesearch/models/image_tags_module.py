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


class ImageTagsModule(Model):
    """Defines the characteristics of content found in an image.

    :param value: A list of tags that describe the characteristics of the
     content found in the image. For example, if the image is of a musical
     artist, the list might include Female, Dress, and Music to indicate the
     person is female music artist that's wearing a dress.
    :type value:
     list[~azure.cognitiveservices.search.imagesearch.models.InsightsTag]
    """

    _validation = {
        'value': {'required': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[InsightsTag]'},
    }

    def __init__(self, value):
        self.value = value
