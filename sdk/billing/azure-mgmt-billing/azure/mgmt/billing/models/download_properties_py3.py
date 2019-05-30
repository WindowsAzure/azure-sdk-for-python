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


class DownloadProperties(Model):
    """The properties of the invoice download.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar kind: Document type. Possible values include: 'Invoice', 'VoidNote',
     'Receipt', 'CreditNote'
    :vartype kind: str or ~azure.mgmt.billing.models.enum
    :ivar url: Document URL.
    :vartype url: str
    """

    _validation = {
        'kind': {'readonly': True},
        'url': {'readonly': True},
    }

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
        'url': {'key': 'url', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(DownloadProperties, self).__init__(**kwargs)
        self.kind = None
        self.url = None
