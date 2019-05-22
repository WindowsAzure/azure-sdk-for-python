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


class RequestStatistics(Model):
    """RequestStatistics.

    :param documents_count: Number of documents submitted in the request.
    :type documents_count: int
    :param valid_documents_count: Number of valid documents. This excludes
     empty, over-size limit or non-supported languages documents.
    :type valid_documents_count: int
    :param erroneous_documents_count: Number of invalid documents. This
     includes empty, over-size limit or non-supported languages documents.
    :type erroneous_documents_count: int
    :param transactions_count: Number of transactions for the request.
    :type transactions_count: long
    """

    _attribute_map = {
        'documents_count': {'key': 'documentsCount', 'type': 'int'},
        'valid_documents_count': {'key': 'validDocumentsCount', 'type': 'int'},
        'erroneous_documents_count': {'key': 'erroneousDocumentsCount', 'type': 'int'},
        'transactions_count': {'key': 'transactionsCount', 'type': 'long'},
    }

    def __init__(self, *, documents_count: int=None, valid_documents_count: int=None, erroneous_documents_count: int=None, transactions_count: int=None, **kwargs) -> None:
        super(RequestStatistics, self).__init__(**kwargs)
        self.documents_count = documents_count
        self.valid_documents_count = valid_documents_count
        self.erroneous_documents_count = erroneous_documents_count
        self.transactions_count = transactions_count
