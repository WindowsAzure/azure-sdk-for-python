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


class ApplicationGatewayFrontendPort(SubResource):
    """Frontend Port of application gateway.

    :param id: Resource Id
    :type id: str
    :param port: Gets or sets the frontend port
    :type port: int
    :param provisioning_state: Gets or sets Provisioning state of the
     frontend port resource Updating/Deleting/Failed
    :type provisioning_state: str
    :param name: Gets name of the resource that is unique within a resource
     group. This name can be used to access the resource
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated
    :type etag: str
    """ 

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'port': {'key': 'properties.port', 'type': 'int'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, id=None, port=None, provisioning_state=None, name=None, etag=None):
        super(ApplicationGatewayFrontendPort, self).__init__(id=id)
        self.port = port
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
