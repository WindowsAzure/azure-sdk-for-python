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


class TopologySingleResourceParent(Model):
    """TopologySingleResourceParent.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar resource_id: Azure resource id which serves as parent resource in
     topology view
    :vartype resource_id: str
    """

    _validation = {
        'resource_id': {'readonly': True},
    }

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(TopologySingleResourceParent, self).__init__(**kwargs)
        self.resource_id = None
