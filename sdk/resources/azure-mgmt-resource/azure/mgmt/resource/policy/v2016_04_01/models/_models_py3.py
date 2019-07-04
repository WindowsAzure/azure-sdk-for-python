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


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class PolicyAssignment(Model):
    """The policy assignment.

    :param display_name: The display name of the policy assignment.
    :type display_name: str
    :param policy_definition_id: The ID of the policy definition.
    :type policy_definition_id: str
    :param scope: The scope for the policy assignment.
    :type scope: str
    :param id: The ID of the policy assignment.
    :type id: str
    :param type: The type of the policy assignment.
    :type type: str
    :param name: The name of the policy assignment.
    :type name: str
    """

    _attribute_map = {
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'policy_definition_id': {'key': 'properties.policyDefinitionId', 'type': 'str'},
        'scope': {'key': 'properties.scope', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, display_name: str=None, policy_definition_id: str=None, scope: str=None, id: str=None, type: str=None, name: str=None, **kwargs) -> None:
        super(PolicyAssignment, self).__init__(**kwargs)
        self.display_name = display_name
        self.policy_definition_id = policy_definition_id
        self.scope = scope
        self.id = id
        self.type = type
        self.name = name


class PolicyDefinition(Model):
    """The policy definition.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param policy_type: The type of policy definition. Possible values are
     NotSpecified, BuiltIn, and Custom. Possible values include:
     'NotSpecified', 'BuiltIn', 'Custom'
    :type policy_type: str or
     ~azure.mgmt.resource.policy.v2016_04_01.models.PolicyType
    :param display_name: The display name of the policy definition.
    :type display_name: str
    :param description: The policy definition description.
    :type description: str
    :param policy_rule: The policy rule.
    :type policy_rule: object
    :ivar id: The ID of the policy definition.
    :vartype id: str
    :param name: The name of the policy definition. If you do not specify a
     value for name, the value is inferred from the name value in the request
     URI.
    :type name: str
    """

    _validation = {
        'id': {'readonly': True},
    }

    _attribute_map = {
        'policy_type': {'key': 'properties.policyType', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'policy_rule': {'key': 'properties.policyRule', 'type': 'object'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(self, *, policy_type=None, display_name: str=None, description: str=None, policy_rule=None, name: str=None, **kwargs) -> None:
        super(PolicyDefinition, self).__init__(**kwargs)
        self.policy_type = policy_type
        self.display_name = display_name
        self.description = description
        self.policy_rule = policy_rule
        self.id = None
        self.name = name
