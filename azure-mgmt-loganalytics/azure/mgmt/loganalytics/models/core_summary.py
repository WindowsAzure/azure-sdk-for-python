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


class CoreSummary(Model):
    """The core summary of a search.

    All required parameters must be populated in order to send to Azure.

    :param status: The status of a core summary.
    :type status: str
    :param number_of_documents: Required. The number of documents of a core
     summary.
    :type number_of_documents: long
    """

    _validation = {
        'number_of_documents': {'required': True},
    }

    _attribute_map = {
        'status': {'key': 'status', 'type': 'str'},
        'number_of_documents': {'key': 'numberOfDocuments', 'type': 'long'},
    }

    def __init__(self, **kwargs):
        super(CoreSummary, self).__init__(**kwargs)
        self.status = kwargs.get('status', None)
        self.number_of_documents = kwargs.get('number_of_documents', None)
