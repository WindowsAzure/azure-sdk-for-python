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


class PredictionQueryTag(Model):
    """PredictionQueryTag.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id:
    :vartype id: str
    :ivar min_threshold:
    :vartype min_threshold: float
    :ivar max_threshold:
    :vartype max_threshold: float
    """

    _validation = {
        'id': {'readonly': True},
        'min_threshold': {'readonly': True},
        'max_threshold': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'min_threshold': {'key': 'minThreshold', 'type': 'float'},
        'max_threshold': {'key': 'maxThreshold', 'type': 'float'},
    }

    def __init__(self, **kwargs):
        super(PredictionQueryTag, self).__init__(**kwargs)
        self.id = None
        self.min_threshold = None
        self.max_threshold = None
