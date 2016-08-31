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

from .resource import Resource


class ReissueCertificateOrderRequest(Resource):
    """Class representing certificate reissue request.

    :param id: Resource Id
    :type id: str
    :param name: Resource Name
    :type name: str
    :param kind: Kind of resource
    :type kind: str
    :param location: Resource Location
    :type location: str
    :param type: Resource type
    :type type: str
    :param tags: Resource tags
    :type tags: dict
    :param key_size: Certificate Key Size
    :type key_size: int
    :param delay_existing_revoke_in_hours: Delay in hours to revoke existing
     certificate after the new certificate is issued
    :type delay_existing_revoke_in_hours: int
    """ 

    _validation = {
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'key_size': {'key': 'properties.keySize', 'type': 'int'},
        'delay_existing_revoke_in_hours': {'key': 'properties.delayExistingRevokeInHours', 'type': 'int'},
    }

    def __init__(self, location, id=None, name=None, kind=None, type=None, tags=None, key_size=None, delay_existing_revoke_in_hours=None):
        super(ReissueCertificateOrderRequest, self).__init__(id=id, name=name, kind=kind, location=location, type=type, tags=tags)
        self.key_size = key_size
        self.delay_existing_revoke_in_hours = delay_existing_revoke_in_hours
