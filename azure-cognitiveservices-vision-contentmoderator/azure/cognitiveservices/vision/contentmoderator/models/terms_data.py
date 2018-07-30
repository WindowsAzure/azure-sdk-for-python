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


class TermsData(Model):
    """All term Id response properties.

    :param language: Language of the terms.
    :type language: str
    :param terms: List of terms.
    :type terms:
     list[~azure.cognitiveservices.vision.contentmoderator.models.TermsInList]
    :param status: Term Status.
    :type status:
     ~azure.cognitiveservices.vision.contentmoderator.models.Status
    :param tracking_id: Tracking Id.
    :type tracking_id: str
    """

    _attribute_map = {
        'language': {'key': 'Language', 'type': 'str'},
        'terms': {'key': 'Terms', 'type': '[TermsInList]'},
        'status': {'key': 'Status', 'type': 'Status'},
        'tracking_id': {'key': 'TrackingId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(TermsData, self).__init__(**kwargs)
        self.language = kwargs.get('language', None)
        self.terms = kwargs.get('terms', None)
        self.status = kwargs.get('status', None)
        self.tracking_id = kwargs.get('tracking_id', None)
