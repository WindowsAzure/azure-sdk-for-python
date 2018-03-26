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


class UserCreateParameters(Model):
    """User create details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :param state: Account state. Specifies whether the user is active or not.
     Blocked users are unable to sign into the developer portal or call any
     APIs of subscribed products. Default state is Active. Possible values
     include: 'active', 'blocked', 'pending', 'deleted'. Default value:
     "active" .
    :type state: str or ~azure.mgmt.apimanagement.models.UserState
    :param note: Optional note about a user set by the administrator.
    :type note: str
    :ivar identities: Collection of user identities.
    :vartype identities:
     list[~azure.mgmt.apimanagement.models.UserIdentityContract]
    :param email: Required. Email address. Must not be empty and must be
     unique within the service instance.
    :type email: str
    :param first_name: Required. First name.
    :type first_name: str
    :param last_name: Required. Last name.
    :type last_name: str
    :param password: User Password. If no value is provided, a default
     password is generated.
    :type password: str
    :param confirmation: Determines the type of confirmation e-mail that will
     be sent to the newly created user. Possible values include: 'signup',
     'invite'
    :type confirmation: str or ~azure.mgmt.apimanagement.models.Confirmation
    """

    _validation = {
        'identities': {'readonly': True},
        'email': {'required': True, 'max_length': 254, 'min_length': 1},
        'first_name': {'required': True, 'max_length': 100, 'min_length': 1},
        'last_name': {'required': True, 'max_length': 100, 'min_length': 1},
    }

    _attribute_map = {
        'state': {'key': 'properties.state', 'type': 'str'},
        'note': {'key': 'properties.note', 'type': 'str'},
        'identities': {'key': 'properties.identities', 'type': '[UserIdentityContract]'},
        'email': {'key': 'properties.email', 'type': 'str'},
        'first_name': {'key': 'properties.firstName', 'type': 'str'},
        'last_name': {'key': 'properties.lastName', 'type': 'str'},
        'password': {'key': 'properties.password', 'type': 'str'},
        'confirmation': {'key': 'properties.confirmation', 'type': 'str'},
    }

    def __init__(self, *, email: str, first_name: str, last_name: str, state="active", note: str=None, password: str=None, confirmation=None, **kwargs) -> None:
        super(UserCreateParameters, self).__init__(**kwargs)
        self.state = state
        self.note = note
        self.identities = None
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.password = password
        self.confirmation = confirmation
