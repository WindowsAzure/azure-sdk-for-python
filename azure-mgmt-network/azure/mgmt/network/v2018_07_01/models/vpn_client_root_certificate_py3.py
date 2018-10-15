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

from .sub_resource_py3 import SubResource


class VpnClientRootCertificate(SubResource):
    """VPN client root certificate of virtual network gateway.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param id: Resource ID.
    :type id: str
    :param public_cert_data: Required. The certificate public data.
    :type public_cert_data: str
    :ivar provisioning_state: The provisioning state of the VPN client root
     certificate resource. Possible values are: 'Updating', 'Deleting', and
     'Failed'.
    :vartype provisioning_state: str
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    """

    _validation = {
        'public_cert_data': {'required': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'public_cert_data': {'key': 'properties.publicCertData', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
    }

    def __init__(self, *, public_cert_data: str, id: str=None, name: str=None, etag: str=None, **kwargs) -> None:
        super(VpnClientRootCertificate, self).__init__(id=id, **kwargs)
        self.public_cert_data = public_cert_data
        self.provisioning_state = None
        self.name = name
        self.etag = etag
