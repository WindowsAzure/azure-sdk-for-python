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


class PolicyAssignment(Model):
    """The policy assignment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param display_name: The display name of the policy assignment.
    :type display_name: str
    :param policy_definition_id: The ID of the policy definition or policy set
     definition being assigned.
    :type policy_definition_id: str
    :param scope: The scope for the policy assignment.
    :type scope: str
    :param not_scopes: The policy's excluded scopes.
    :type not_scopes: list[str]
    :param parameters: Required if a parameter is used in policy rule.
    :type parameters: object
    :param description: This message will be part of response in case of
     policy violation.
    :type description: str
    :param metadata: The policy assignment metadata.
    :type metadata: object
    :ivar id: The ID of the policy assignment.
    :vartype id: str
    :ivar type: The type of the policy assignment.
    :vartype type: str
    :ivar name: The name of the policy assignment.
    :vartype name: str
    :param sku: The policy sku. This property is optional, obsolete, and will
     be ignored.
    :type sku: ~azure.mgmt.resource.policy.v2018_03_01.models.PolicySku
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
    }

    _attribute_map = {
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'policy_definition_id': {'key': 'properties.policyDefinitionId', 'type': 'str'},
        'scope': {'key': 'properties.scope', 'type': 'str'},
        'not_scopes': {'key': 'properties.notScopes', 'type': '[str]'},
        'parameters': {'key': 'properties.parameters', 'type': 'object'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'metadata': {'key': 'properties.metadata', 'type': 'object'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'sku': {'key': 'sku', 'type': 'PolicySku'},
    }

    def __init__(self, **kwargs):
        super(PolicyAssignment, self).__init__(**kwargs)
        self.display_name = kwargs.get('display_name', None)
        self.policy_definition_id = kwargs.get('policy_definition_id', None)
        self.scope = kwargs.get('scope', None)
        self.not_scopes = kwargs.get('not_scopes', None)
        self.parameters = kwargs.get('parameters', None)
        self.description = kwargs.get('description', None)
        self.metadata = kwargs.get('metadata', None)
        self.id = None
        self.type = None
        self.name = None
        self.sku = kwargs.get('sku', None)
