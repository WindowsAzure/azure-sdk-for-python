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

from .artifact import Artifact


class PolicyAssignmentArtifact(Artifact):
    """Blueprint artifact that applies a Policy assignment.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: String Id used to locate any resource on Azure.
    :vartype id: str
    :ivar type: Type of this resource.
    :vartype type: str
    :ivar name: Name of this resource.
    :vartype name: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param display_name: One-liner string explain this resource.
    :type display_name: str
    :param description: Multi-line explain this resource.
    :type description: str
    :param depends_on: Artifacts which need to be deployed before the
     specified artifact.
    :type depends_on: list[str]
    :param policy_definition_id: Required. Azure resource ID of the policy
     definition.
    :type policy_definition_id: str
    :param parameters: Required. Parameter values for the policy definition.
    :type parameters: dict[str,
     ~azure.mgmt.blueprint.models.ParameterValueBase]
    :param resource_group: Name of the resource group placeholder to which the
     policy will be assigned.
    :type resource_group: str
    """

    _validation = {
        'id': {'readonly': True},
        'type': {'readonly': True},
        'name': {'readonly': True},
        'kind': {'required': True},
        'display_name': {'max_length': 256},
        'description': {'max_length': 500},
        'policy_definition_id': {'required': True},
        'parameters': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'depends_on': {'key': 'properties.dependsOn', 'type': '[str]'},
        'policy_definition_id': {'key': 'properties.policyDefinitionId', 'type': 'str'},
        'parameters': {'key': 'properties.parameters', 'type': '{ParameterValueBase}'},
        'resource_group': {'key': 'properties.resourceGroup', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(PolicyAssignmentArtifact, self).__init__(**kwargs)
        self.display_name = kwargs.get('display_name', None)
        self.description = kwargs.get('description', None)
        self.depends_on = kwargs.get('depends_on', None)
        self.policy_definition_id = kwargs.get('policy_definition_id', None)
        self.parameters = kwargs.get('parameters', None)
        self.resource_group = kwargs.get('resource_group', None)
        self.kind = 'policyAssignment'
