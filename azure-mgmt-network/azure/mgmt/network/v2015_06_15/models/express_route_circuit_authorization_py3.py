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

    :param id: Resource Identifier.
    :type id: str
    :param authorization_key: The authorization key.
    :type authorization_key: str
    :param authorization_use_status: AuthorizationUseStatus. Possible values
     are: 'Available' and 'InUse'. Possible values include: 'Available',
     'InUse'
    :type authorization_use_status: str or
     ~azure.mgmt.network.v2015_06_15.models.AuthorizationUseStatus
    :param provisioning_state: Gets the provisioning state of the public IP
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param name: Gets name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'authorization_key': {'key': 'properties.authorizationKey', 'type': 'str'},
        'authorization_use_status': {'key': 'properties.authorizationUseStatus', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, authorization_key: str=None, authorization_use_status=None, provisioning_state: str=None, name: str=None, etag: str=None, **kwargs) -> None:
        super(ExpressRouteCircuitAuthorization, self).__init__(id=id, **kwargs)
        self.authorization_key = authorization_key
        self.authorization_use_status = authorization_use_status
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
