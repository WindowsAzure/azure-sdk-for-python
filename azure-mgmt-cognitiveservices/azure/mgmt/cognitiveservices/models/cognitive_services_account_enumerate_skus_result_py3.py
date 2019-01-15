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


class CognitiveServicesAccountEnumerateSkusResult(Model):
    """The list of cognitive services accounts operation response.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar value: Gets the list of Cognitive Services accounts and their
     properties.
    :vartype value:
     list[~azure.mgmt.cognitiveservices.models.CognitiveServicesResourceAndSku]
    """

    _validation = {
        'value': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[CognitiveServicesResourceAndSku]'},
    }

    def __init__(self, **kwargs) -> None:
        super(CognitiveServicesAccountEnumerateSkusResult, self).__init__(**kwargs)
        self.value = None
