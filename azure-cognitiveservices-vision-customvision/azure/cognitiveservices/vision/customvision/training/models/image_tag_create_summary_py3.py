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


class ImageTagCreateSummary(Model):
    """ImageTagCreateSummary.

    :param created:
    :type created:
     list[~azure.cognitiveservices.vision.customvision.training.models.ImageTagCreateEntry]
    :param duplicated:
    :type duplicated:
     list[~azure.cognitiveservices.vision.customvision.training.models.ImageTagCreateEntry]
    :param exceeded:
    :type exceeded:
     list[~azure.cognitiveservices.vision.customvision.training.models.ImageTagCreateEntry]
    """

    _attribute_map = {
        'created': {'key': 'Created', 'type': '[ImageTagCreateEntry]'},
        'duplicated': {'key': 'Duplicated', 'type': '[ImageTagCreateEntry]'},
        'exceeded': {'key': 'Exceeded', 'type': '[ImageTagCreateEntry]'},
    }

    def __init__(self, *, created=None, duplicated=None, exceeded=None, **kwargs) -> None:
        super(ImageTagCreateSummary, self).__init__(**kwargs)
        self.created = created
        self.duplicated = duplicated
        self.exceeded = exceeded
