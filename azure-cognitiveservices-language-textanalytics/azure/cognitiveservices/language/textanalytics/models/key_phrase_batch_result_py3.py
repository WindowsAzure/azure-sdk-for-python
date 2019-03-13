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


class KeyPhraseBatchResult(Model):
    """KeyPhraseBatchResult.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar documents: Response by document
    :vartype documents:
     list[~azure.cognitiveservices.language.textanalytics.models.KeyPhraseBatchResultItem]
    :ivar errors: Errors and Warnings by document
    :vartype errors:
     list[~azure.cognitiveservices.language.textanalytics.models.ErrorRecord]
    :ivar statistics: =(Optional) if showStats=true was specified in the
     request this field will contain information about the request payload.
    :vartype statistics:
     ~azure.cognitiveservices.language.textanalytics.models.RequestStatistics
    """

    _validation = {
        'documents': {'readonly': True},
        'errors': {'readonly': True},
        'statistics': {'readonly': True},
    }

    _attribute_map = {
        'documents': {'key': 'documents', 'type': '[KeyPhraseBatchResultItem]'},
        'errors': {'key': 'errors', 'type': '[ErrorRecord]'},
        'statistics': {'key': 'statistics', 'type': 'RequestStatistics'},
    }

    def __init__(self, **kwargs) -> None:
        super(KeyPhraseBatchResult, self).__init__(**kwargs)
        self.documents = None
        self.errors = None
        self.statistics = None
