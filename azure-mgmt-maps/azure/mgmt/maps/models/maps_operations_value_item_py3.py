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


class MapsOperationsValueItem(Model):
    """MapsOperationsValueItem.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: Operation name: {provider}/{resource}/{operation}.
    :vartype name: str
    :param display: The human-readable description of the operation.
    :type display: ~azure.mgmt.maps.models.MapsOperationsValueItemDisplay
    :ivar origin: The origin of the operation.
    :vartype origin: str
    """

    _validation = {
        'name': {'readonly': True},
        'origin': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'MapsOperationsValueItemDisplay'},
        'origin': {'key': 'origin', 'type': 'str'},
    }

    def __init__(self, *, display=None, **kwargs) -> None:
        super(MapsOperationsValueItem, self).__init__(**kwargs)
        self.name = None
        self.display = display
        self.origin = None
