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

from .sub_resource import SubResource


class ExpressRouteCircuitAuthorization(SubResource):
    """Authorization in an ExpressRouteCircuit resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param authorization_key: The authorization key.
    :type authorization_key: str
    :param authorization_use_status: AuthorizationUseStatus. Possible values
     are: 'Available' and 'InUse'. Possible values include: 'Available',
     'InUse'
    :type authorization_use_status: str or
     ~azure.mgmt.network.v2018_06_01.models.AuthorizationUseStatus
    :param provisioning_state: Gets the provisioning state of the public IP
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param name: Gets name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    """

    _validation = {
        'etag': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'authorization_key': {'key': 'properties.authorizationKey', 'type': 'str'},
        'authorization_use_status': {'key': 'properties.authorizationUseStatus', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ExpressRouteCircuitAuthorization, self).__init__(**kwargs)
        self.authorization_key = kwargs.get('authorization_key', None)
        self.authorization_use_status = kwargs.get('authorization_use_status', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.name = kwargs.get('name', None)
        self.etag = None
