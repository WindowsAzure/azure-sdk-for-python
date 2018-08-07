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


class PolicyState(Model):
    """Policy state record.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param odataid: OData entity ID; always set to null since policy state
     records do not have an entity ID.
    :type odataid: str
    :param odatacontext: OData context string; used by OData clients to
     resolve type information based on metadata.
    :type odatacontext: str
    :param timestamp: Timestamp for the policy state record.
    :type timestamp: datetime
    :param resource_id: Resource ID.
    :type resource_id: str
    :param policy_assignment_id: Policy assignment ID.
    :type policy_assignment_id: str
    :param policy_definition_id: Policy definition ID.
    :type policy_definition_id: str
    :param effective_parameters: Effective parameters for the policy
     assignment.
    :type effective_parameters: str
    :param is_compliant: Flag which states whether the resource is compliant
     against the policy assignment it was evaluated against.
    :type is_compliant: bool
    :param subscription_id: Subscription ID.
    :type subscription_id: str
    :param resource_type: Resource type.
    :type resource_type: str
    :param resource_location: Resource location.
    :type resource_location: str
    :param resource_group: Resource group name.
    :type resource_group: str
    :param resource_tags: List of resource tags.
    :type resource_tags: str
    :param policy_assignment_name: Policy assignment name.
    :type policy_assignment_name: str
    :param policy_assignment_owner: Policy assignment owner.
    :type policy_assignment_owner: str
    :param policy_assignment_parameters: Policy assignment parameters.
    :type policy_assignment_parameters: str
    :param policy_assignment_scope: Policy assignment scope.
    :type policy_assignment_scope: str
    :param policy_definition_name: Policy definition name.
    :type policy_definition_name: str
    :param policy_definition_action: Policy definition action, i.e. effect.
    :type policy_definition_action: str
    :param policy_definition_category: Policy definition category.
    :type policy_definition_category: str
    :param policy_set_definition_id: Policy set definition ID, if the policy
     assignment is for a policy set.
    :type policy_set_definition_id: str
    :param policy_set_definition_name: Policy set definition name, if the
     policy assignment is for a policy set.
    :type policy_set_definition_name: str
    :param policy_set_definition_owner: Policy set definition owner, if the
     policy assignment is for a policy set.
    :type policy_set_definition_owner: str
    :param policy_set_definition_category: Policy set definition category, if
     the policy assignment is for a policy set.
    :type policy_set_definition_category: str
    :param policy_set_definition_parameters: Policy set definition parameters,
     if the policy assignment is for a policy set.
    :type policy_set_definition_parameters: str
    :param management_group_ids: Comma seperated list of management group IDs,
     which represent the hierarchy of the management groups the resource is
     under.
    :type management_group_ids: str
    :param policy_definition_reference_id: Reference ID for the policy
     definition inside the policy set, if the policy assignment is for a policy
     set.
    :type policy_definition_reference_id: str
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'odataid': {'key': '@odata\\.id', 'type': 'str'},
        'odatacontext': {'key': '@odata\\.context', 'type': 'str'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'policy_assignment_id': {'key': 'policyAssignmentId', 'type': 'str'},
        'policy_definition_id': {'key': 'policyDefinitionId', 'type': 'str'},
        'effective_parameters': {'key': 'effectiveParameters', 'type': 'str'},
        'is_compliant': {'key': 'isCompliant', 'type': 'bool'},
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'resource_type': {'key': 'resourceType', 'type': 'str'},
        'resource_location': {'key': 'resourceLocation', 'type': 'str'},
        'resource_group': {'key': 'resourceGroup', 'type': 'str'},
        'resource_tags': {'key': 'resourceTags', 'type': 'str'},
        'policy_assignment_name': {'key': 'policyAssignmentName', 'type': 'str'},
        'policy_assignment_owner': {'key': 'policyAssignmentOwner', 'type': 'str'},
        'policy_assignment_parameters': {'key': 'policyAssignmentParameters', 'type': 'str'},
        'policy_assignment_scope': {'key': 'policyAssignmentScope', 'type': 'str'},
        'policy_definition_name': {'key': 'policyDefinitionName', 'type': 'str'},
        'policy_definition_action': {'key': 'policyDefinitionAction', 'type': 'str'},
        'policy_definition_category': {'key': 'policyDefinitionCategory', 'type': 'str'},
        'policy_set_definition_id': {'key': 'policySetDefinitionId', 'type': 'str'},
        'policy_set_definition_name': {'key': 'policySetDefinitionName', 'type': 'str'},
        'policy_set_definition_owner': {'key': 'policySetDefinitionOwner', 'type': 'str'},
        'policy_set_definition_category': {'key': 'policySetDefinitionCategory', 'type': 'str'},
        'policy_set_definition_parameters': {'key': 'policySetDefinitionParameters', 'type': 'str'},
        'management_group_ids': {'key': 'managementGroupIds', 'type': 'str'},
        'policy_definition_reference_id': {'key': 'policyDefinitionReferenceId', 'type': 'str'},
    }

    def __init__(self, *, additional_properties=None, odataid: str=None, odatacontext: str=None, timestamp=None, resource_id: str=None, policy_assignment_id: str=None, policy_definition_id: str=None, effective_parameters: str=None, is_compliant: bool=None, subscription_id: str=None, resource_type: str=None, resource_location: str=None, resource_group: str=None, resource_tags: str=None, policy_assignment_name: str=None, policy_assignment_owner: str=None, policy_assignment_parameters: str=None, policy_assignment_scope: str=None, policy_definition_name: str=None, policy_definition_action: str=None, policy_definition_category: str=None, policy_set_definition_id: str=None, policy_set_definition_name: str=None, policy_set_definition_owner: str=None, policy_set_definition_category: str=None, policy_set_definition_parameters: str=None, management_group_ids: str=None, policy_definition_reference_id: str=None, **kwargs) -> None:
        super(PolicyState, self).__init__(**kwargs)
        self.additional_properties = additional_properties
        self.odataid = odataid
        self.odatacontext = odatacontext
        self.timestamp = timestamp
        self.resource_id = resource_id
        self.policy_assignment_id = policy_assignment_id
        self.policy_definition_id = policy_definition_id
        self.effective_parameters = effective_parameters
        self.is_compliant = is_compliant
        self.subscription_id = subscription_id
        self.resource_type = resource_type
        self.resource_location = resource_location
        self.resource_group = resource_group
        self.resource_tags = resource_tags
        self.policy_assignment_name = policy_assignment_name
        self.policy_assignment_owner = policy_assignment_owner
        self.policy_assignment_parameters = policy_assignment_parameters
        self.policy_assignment_scope = policy_assignment_scope
        self.policy_definition_name = policy_definition_name
        self.policy_definition_action = policy_definition_action
        self.policy_definition_category = policy_definition_category
        self.policy_set_definition_id = policy_set_definition_id
        self.policy_set_definition_name = policy_set_definition_name
        self.policy_set_definition_owner = policy_set_definition_owner
        self.policy_set_definition_category = policy_set_definition_category
        self.policy_set_definition_parameters = policy_set_definition_parameters
        self.management_group_ids = management_group_ids
        self.policy_definition_reference_id = policy_definition_reference_id
