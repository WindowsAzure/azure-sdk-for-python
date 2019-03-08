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


class AddUsersPayload(Model):
    """Payload for Add Users operation on a Lab.

    All required parameters must be populated in order to send to Azure.

    :param email_addresses: Required. List of user emails addresses to add to
     the lab.
    :type email_addresses: list[str]
    """

    _validation = {
        'email_addresses': {'required': True},
    }

    _attribute_map = {
        'email_addresses': {'key': 'emailAddresses', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(AddUsersPayload, self).__init__(**kwargs)
        self.email_addresses = kwargs.get('email_addresses', None)
