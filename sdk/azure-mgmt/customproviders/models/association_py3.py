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


class Association(Model):
    """The resource definition of this association.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The association id.
    :vartype id: str
    :ivar name: The association name.
    :vartype name: str
    :ivar type: The association type.
    :vartype type: str
    :param target_resource_id: The REST resource instance of the target
     resource for this association.
    :type target_resource_id: str
    :ivar provisioning_state: The provisioning state of the association.
     Possible values include: 'Accepted', 'Deleting', 'Running', 'Succeeded',
     'Failed'
    :vartype provisioning_state: str or
     ~microsoft.customproviders.models.ProvisioningState
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'target_resource_id': {'key': 'properties.targetResourceId', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(self, *, target_resource_id: str=None, **kwargs) -> None:
        super(Association, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.target_resource_id = target_resource_id
        self.provisioning_state = None
