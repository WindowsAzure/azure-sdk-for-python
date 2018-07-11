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


class Contacts(Model):
    """The contacts for the vault certificates.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Identifier for the contacts collection.
    :vartype id: str
    :param contact_list: The contact list for the vault certificates.
    :type contact_list: list[~azure.keyvault.models.Contact]
    """

    _validation = {
        'id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'contact_list': {'key': 'contacts', 'type': '[Contact]'},
    }

    def __init__(self, *, contact_list=None, **kwargs) -> None:
        super(Contacts, self).__init__(**kwargs)
        self.id = None
        self.contact_list = contact_list
