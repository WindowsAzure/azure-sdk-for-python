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

from .resource_py3 import Resource


class PriceSheetResult(Resource):
    """An pricesheet resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar tags: Resource tags.
    :vartype tags: dict[str, str]
    :ivar pricesheets: Price sheet
    :vartype pricesheets:
     list[~azure.mgmt.consumption.models.PriceSheetProperties]
    :ivar next_link: The link (url) to the next page of results.
    :vartype next_link: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
        'pricesheets': {'readonly': True},
        'next_link': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'pricesheets': {'key': 'properties.pricesheets', 'type': '[PriceSheetProperties]'},
        'next_link': {'key': 'properties.nextLink', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(PriceSheetResult, self).__init__(**kwargs)
        self.pricesheets = None
        self.next_link = None
