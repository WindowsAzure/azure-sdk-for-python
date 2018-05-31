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


class ImagesModule(Model):
    """Defines a list of images.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar value: A list of images.
    :vartype value:
     list[~azure.cognitiveservices.search.imagesearch.models.ImageObject]
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ImageObject]'},
    }

    def __init__(self, **kwargs):
        super(ImagesModule, self).__init__(**kwargs)
        self.value = None
