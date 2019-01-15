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


class RegionProposal(Model):
    """RegionProposal.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar confidence:
    :vartype confidence: float
    :ivar bounding_box:
    :vartype bounding_box:
     ~azure.cognitiveservices.vision.customvision.training.models.BoundingBox
    """

    _validation = {
        'confidence': {'readonly': True},
        'bounding_box': {'readonly': True},
    }

    _attribute_map = {
        'confidence': {'key': 'confidence', 'type': 'float'},
        'bounding_box': {'key': 'boundingBox', 'type': 'BoundingBox'},
    }

    def __init__(self, **kwargs) -> None:
        super(RegionProposal, self).__init__(**kwargs)
        self.confidence = None
        self.bounding_box = None
