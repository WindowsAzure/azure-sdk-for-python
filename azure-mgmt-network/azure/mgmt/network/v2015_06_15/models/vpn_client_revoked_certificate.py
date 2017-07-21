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


class VpnClientRevokedCertificate(SubResource):
    """VPN client revoked certificate of virtual network gateway.

    :param id: Resource Identifier.
    :type id: str
    :param thumbprint: The revoked VPN client certificate thumbprint.
    :type thumbprint: str
    :param provisioning_state: The provisioning state of the VPN client
     revoked certificate resource. Possible values are: 'Updating', 'Deleting',
     and 'Failed'.
    :type provisioning_state: str
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'thumbprint': {'key': 'properties.thumbprint', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, id=None, thumbprint=None, provisioning_state=None, name=None, etag=None):
        super(VpnClientRevokedCertificate, self).__init__(id=id)
        self.thumbprint = thumbprint
        self.provisioning_state = provisioning_state
        self.name = name
        self.etag = etag
