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


class OperationListResult(Model):
    """The list of available operations for Data Lake Analytics.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar value: the results of the list operation.
    :vartype value:
     list[~azure.mgmt.datalake.analytics.account.models.Operation]
    :ivar next_link: the link (url) to the next page of results.
    :vartype next_link: str
    """

    _validation = {
        'value': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Operation]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(self):
        self.value = None
        self.next_link = None
