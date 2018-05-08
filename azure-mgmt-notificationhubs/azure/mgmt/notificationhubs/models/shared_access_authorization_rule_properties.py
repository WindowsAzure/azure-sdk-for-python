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


class SharedAccessAuthorizationRuleProperties(Model):
    """SharedAccessAuthorizationRule properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param rights: The rights associated with the rule.
    :type rights: list[str or
     ~azure.mgmt.notificationhubs.models.AccessRights]
    :ivar primary_key: A base64-encoded 256-bit primary key for signing and
     validating the SAS token.
    :vartype primary_key: str
    :ivar secondary_key: A base64-encoded 256-bit primary key for signing and
     validating the SAS token.
    :vartype secondary_key: str
    :ivar key_name: A string that describes the authorization rule.
    :vartype key_name: str
    :ivar claim_type: A string that describes the claim type
    :vartype claim_type: str
    :ivar claim_value: A string that describes the claim value
    :vartype claim_value: str
    :ivar modified_time: The last modified time for this rule
    :vartype modified_time: str
    :ivar created_time: The created time for this rule
    :vartype created_time: str
    :ivar revision: The revision number for the rule
    :vartype revision: int
    """

    _validation = {
        'primary_key': {'readonly': True},
        'secondary_key': {'readonly': True},
        'key_name': {'readonly': True},
        'claim_type': {'readonly': True},
        'claim_value': {'readonly': True},
        'modified_time': {'readonly': True},
        'created_time': {'readonly': True},
        'revision': {'readonly': True},
    }

    _attribute_map = {
        'rights': {'key': 'rights', 'type': '[AccessRights]'},
        'primary_key': {'key': 'primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'secondaryKey', 'type': 'str'},
        'key_name': {'key': 'keyName', 'type': 'str'},
        'claim_type': {'key': 'claimType', 'type': 'str'},
        'claim_value': {'key': 'claimValue', 'type': 'str'},
        'modified_time': {'key': 'modifiedTime', 'type': 'str'},
        'created_time': {'key': 'createdTime', 'type': 'str'},
        'revision': {'key': 'revision', 'type': 'int'},
    }

    def __init__(self, **kwargs):
        super(SharedAccessAuthorizationRuleProperties, self).__init__(**kwargs)
        self.rights = kwargs.get('rights', None)
        self.primary_key = None
        self.secondary_key = None
        self.key_name = None
        self.claim_type = None
        self.claim_value = None
        self.modified_time = None
        self.created_time = None
        self.revision = None
