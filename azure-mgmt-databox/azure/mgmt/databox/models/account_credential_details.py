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


class AccountCredentialDetails(Model):
    """Credential details of the account.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar account_name: Name of the account.
    :vartype account_name: str
    :ivar account_connection_string: Connection string of the account endpoint
     to use the account as a storage endpoint on the device.
    :vartype account_connection_string: str
    :ivar share_credential_details: Per share level unencrypted access
     credentials.
    :vartype share_credential_details:
     list[~azure.mgmt.databox.models.ShareCredentialDetails]
    """

    _validation = {
        'account_name': {'readonly': True},
        'account_connection_string': {'readonly': True},
        'share_credential_details': {'readonly': True},
    }

    _attribute_map = {
        'account_name': {'key': 'accountName', 'type': 'str'},
        'account_connection_string': {'key': 'accountConnectionString', 'type': 'str'},
        'share_credential_details': {'key': 'shareCredentialDetails', 'type': '[ShareCredentialDetails]'},
    }

    def __init__(self, **kwargs):
        super(AccountCredentialDetails, self).__init__(**kwargs)
        self.account_name = None
        self.account_connection_string = None
        self.share_credential_details = None
