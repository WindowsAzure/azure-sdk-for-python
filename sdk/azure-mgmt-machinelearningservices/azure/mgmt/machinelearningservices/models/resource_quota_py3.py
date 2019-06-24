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


class ResourceQuota(Model):
    """The quota assigned to a resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Specifies the resource ID.
    :vartype id: str
    :ivar type: Specifies the resource type.
    :vartype type: str
    :ivar name: Name of the resource.
    :vartype name: ~azure.mgmt.machinelearningservices.models.ResourceName
    :ivar limit: Limit. The maximum permitted quota of the resource.
    :vartype limit: long
    :ivar unit: An enum describing the unit of quota measurement. Possible
     values include: 'Count'
    :vartype unit: str or ~azure.mgmt.machinelearningservices.models.QuotaUnit
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'limit': {'readonly': True},
        'unit': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'ResourceName'},
        'limit': {'key': 'limit', 'type': 'long'},
        'unit': {'key': 'unit', 'type': 'str'},
    }

    def __init__(self, **kwargs) -> None:
        super(ResourceQuota, self).__init__(**kwargs)
        self.id = None
        self.type = None
        self.name = None
        self.limit = None
        self.unit = None
