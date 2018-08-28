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


class EventsUserInfo(Model):
    """User info for an event result.

    :param id: ID of the user
    :type id: str
    :param account_id: Account ID of the user
    :type account_id: str
    :param authenticated_id: Authenticated ID of the user
    :type authenticated_id: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'account_id': {'key': 'accountId', 'type': 'str'},
        'authenticated_id': {'key': 'authenticatedId', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, account_id: str=None, authenticated_id: str=None, **kwargs) -> None:
        super(EventsUserInfo, self).__init__(**kwargs)
        self.id = id
        self.account_id = account_id
        self.authenticated_id = authenticated_id
