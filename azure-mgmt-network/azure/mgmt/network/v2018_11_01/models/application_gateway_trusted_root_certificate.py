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


class ApplicationGatewayTrustedRootCertificate(SubResource):
    """Trusted Root certificates of an application gateway.

    :param id: Resource ID.
    :type id: str
    :param data: Certificate public data.
    :type data: str
    :param key_vault_secret_id: Secret Id of (base-64 encoded unencrypted pfx)
     'Secret' or 'Certificate' object stored in KeyVault.
    :type key_vault_secret_id: str
    :param provisioning_state: Provisioning state of the trusted root
     certificate resource. Possible values are: 'Updating', 'Deleting', and
     'Failed'.
    :type provisioning_state: str
    :param name: Name of the trusted root certificate that is unique within an
     Application Gateway.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    :param type: Type of the resource.
    :type type: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'data': {'key': 'properties.data', 'type': 'str'},
        'key_vault_secret_id': {'key': 'properties.keyVaultSecretId', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ApplicationGatewayTrustedRootCertificate, self).__init__(**kwargs)
        self.data = kwargs.get('data', None)
        self.key_vault_secret_id = kwargs.get('key_vault_secret_id', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.name = kwargs.get('name', None)
        self.etag = kwargs.get('etag', None)
        self.type = kwargs.get('type', None)
