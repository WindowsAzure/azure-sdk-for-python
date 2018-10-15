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

from .resource_py3 import Resource


class User(Resource):
    """Profile of a lab user.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The identifier of the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param location: The location of the resource.
    :type location: str
    :param tags: The tags of the resource.
    :type tags: dict[str, str]
    :param identity: The identity of the user.
    :type identity: ~azure.mgmt.devtestlabs.models.UserIdentity
    :param secret_store: The secret store of the user.
    :type secret_store: ~azure.mgmt.devtestlabs.models.UserSecretStore
    :ivar created_date: The creation date of the user profile.
    :vartype created_date: datetime
    :param provisioning_state: The provisioning status of the resource.
    :type provisioning_state: str
    :param unique_identifier: The unique immutable identifier of a resource
     (Guid).
    :type unique_identifier: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created_date': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'identity': {'key': 'properties.identity', 'type': 'UserIdentity'},
        'secret_store': {'key': 'properties.secretStore', 'type': 'UserSecretStore'},
        'created_date': {'key': 'properties.createdDate', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'unique_identifier': {'key': 'properties.uniqueIdentifier', 'type': 'str'},
    }

    def __init__(self, *, location: str=None, tags=None, identity=None, secret_store=None, provisioning_state: str=None, unique_identifier: str=None, **kwargs) -> None:
        super(User, self).__init__(location=location, tags=tags, **kwargs)
        self.identity = identity
        self.secret_store = secret_store
        self.created_date = None
        self.provisioning_state = provisioning_state
        self.unique_identifier = unique_identifier
