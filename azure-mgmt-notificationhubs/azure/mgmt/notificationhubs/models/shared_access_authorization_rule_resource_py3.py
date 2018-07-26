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


class SharedAccessAuthorizationRuleResource(Resource):
    """Description of a Namespace AuthorizationRules.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param sku: The sku of the created namespace
    :type sku: ~azure.mgmt.notificationhubs.models.Sku
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
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
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
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'Sku'},
        'rights': {'key': 'properties.rights', 'type': '[AccessRights]'},
        'primary_key': {'key': 'properties.primaryKey', 'type': 'str'},
        'secondary_key': {'key': 'properties.secondaryKey', 'type': 'str'},
        'key_name': {'key': 'properties.keyName', 'type': 'str'},
        'claim_type': {'key': 'properties.claimType', 'type': 'str'},
        'claim_value': {'key': 'properties.claimValue', 'type': 'str'},
        'modified_time': {'key': 'properties.modifiedTime', 'type': 'str'},
        'created_time': {'key': 'properties.createdTime', 'type': 'str'},
        'revision': {'key': 'properties.revision', 'type': 'int'},
    }

    def __init__(self, *, location: str=None, tags=None, sku=None, rights=None, **kwargs) -> None:
        super(SharedAccessAuthorizationRuleResource, self).__init__(location=location, tags=tags, sku=sku, **kwargs)
        self.rights = rights
        self.primary_key = None
        self.secondary_key = None
        self.key_name = None
        self.claim_type = None
        self.claim_value = None
        self.modified_time = None
        self.created_time = None
        self.revision = None
