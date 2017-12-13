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


class Terms(Model):
    """Terms properties.

    :param data: Term data details.
    :type data: ~azure.cognitiveservices.contentmoderator.models.TermsData
    :param paging: Paging details.
    :type paging: ~azure.cognitiveservices.contentmoderator.models.TermsPaging
    """

    _attribute_map = {
        'data': {'key': 'data', 'type': 'TermsData'},
        'paging': {'key': 'paging', 'type': 'TermsPaging'},
    }

    def __init__(self, data=None, paging=None):
        self.data = data
        self.paging = paging
