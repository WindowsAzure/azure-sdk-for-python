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


class Domain(Model):
    """Domain.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id:
    :vartype id: str
    :ivar name:
    :vartype name: str
    :ivar type: Possible values include: 'Classification', 'ObjectDetection'
    :vartype type: str or
     ~azure.cognitiveservices.vision.customvision.training.models.DomainType
    :ivar exportable:
    :vartype exportable: bool
    :ivar enabled:
    :vartype enabled: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'exportable': {'readonly': True},
        'enabled': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'exportable': {'key': 'exportable', 'type': 'bool'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
    }

    def __init__(self, **kwargs):
        super(Domain, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.exportable = None
        self.enabled = None
