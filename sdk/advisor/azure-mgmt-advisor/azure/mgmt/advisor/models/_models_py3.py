# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import datetime
from typing import Any, Dict, List, Optional, Union

from azure.core.exceptions import HttpResponseError
import msrest.serialization

from ._advisor_management_client_enums import *


class ArmErrorResponse(msrest.serialization.Model):
    """ArmErrorResponse.

    :param error: ARM error response body.
    :type error: ~azure.mgmt.advisor.models.ARMErrorResponseBody
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ARMErrorResponseBody'},
    }

    def __init__(
        self,
        *,
        error: Optional["ARMErrorResponseBody"] = None,
        **kwargs
    ):
        super(ArmErrorResponse, self).__init__(**kwargs)
        self.error = error


class ARMErrorResponseBody(msrest.serialization.Model):
    """ARM error response body.

    :param message: Gets or sets the string that describes the error in detail and provides
     debugging information.
    :type message: str
    :param code: Gets or sets the string that can be used to programmatically identify the error.
    :type code: str
    """

    _attribute_map = {
        'message': {'key': 'message', 'type': 'str'},
        'code': {'key': 'code', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        message: Optional[str] = None,
        code: Optional[str] = None,
        **kwargs
    ):
        super(ARMErrorResponseBody, self).__init__(**kwargs)
        self.message = message
        self.code = code


class Resource(msrest.serialization.Model):
    """An Azure resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class ConfigData(Resource):
    """The Advisor configuration data structure.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param exclude: Exclude the resource from Advisor evaluations. Valid values: False (default) or
     True.
    :type exclude: bool
    :param low_cpu_threshold: Minimum percentage threshold for Advisor low CPU utilization
     evaluation. Valid only for subscriptions. Valid values: 5 (default), 10, 15 or 20. Possible
     values include: "5", "10", "15", "20".
    :type low_cpu_threshold: str or ~azure.mgmt.advisor.models.CpuThreshold
    :param digests: Advisor digest configuration. Valid only for subscriptions.
    :type digests: list[~azure.mgmt.advisor.models.DigestConfig]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'exclude': {'key': 'properties.exclude', 'type': 'bool'},
        'low_cpu_threshold': {'key': 'properties.lowCpuThreshold', 'type': 'str'},
        'digests': {'key': 'properties.digests', 'type': '[DigestConfig]'},
    }

    def __init__(
        self,
        *,
        exclude: Optional[bool] = None,
        low_cpu_threshold: Optional[Union[str, "CpuThreshold"]] = None,
        digests: Optional[List["DigestConfig"]] = None,
        **kwargs
    ):
        super(ConfigData, self).__init__(**kwargs)
        self.exclude = exclude
        self.low_cpu_threshold = low_cpu_threshold
        self.digests = digests


class ConfigurationListResult(msrest.serialization.Model):
    """The list of Advisor configurations.

    :param value: The list of configurations.
    :type value: list[~azure.mgmt.advisor.models.ConfigData]
    :param next_link: The link used to get the next page of configurations.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ConfigData]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["ConfigData"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(ConfigurationListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class DigestConfig(msrest.serialization.Model):
    """Advisor Digest configuration entity.

    :param name: Name of digest configuration. Value is case-insensitive and must be unique within
     a subscription.
    :type name: str
    :param action_group_resource_id: Action group resource id used by digest.
    :type action_group_resource_id: str
    :param frequency: Frequency that digest will be triggered, in days. Value must be between 7 and
     30 days inclusive.
    :type frequency: int
    :param categories: Categories to send digest for. If categories are not provided, then digest
     will be sent for all categories.
    :type categories: list[str or ~azure.mgmt.advisor.models.Category]
    :param language: Language for digest content body. Value must be ISO 639-1 code for one of
     Azure portal supported languages. Otherwise, it will be converted into one. Default value is
     English (en).
    :type language: str
    :param state: State of digest configuration. Possible values include: "Active", "Disabled".
    :type state: str or ~azure.mgmt.advisor.models.DigestConfigState
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'action_group_resource_id': {'key': 'actionGroupResourceId', 'type': 'str'},
        'frequency': {'key': 'frequency', 'type': 'int'},
        'categories': {'key': 'categories', 'type': '[str]'},
        'language': {'key': 'language', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        action_group_resource_id: Optional[str] = None,
        frequency: Optional[int] = None,
        categories: Optional[List[Union[str, "Category"]]] = None,
        language: Optional[str] = None,
        state: Optional[Union[str, "DigestConfigState"]] = None,
        **kwargs
    ):
        super(DigestConfig, self).__init__(**kwargs)
        self.name = name
        self.action_group_resource_id = action_group_resource_id
        self.frequency = frequency
        self.categories = categories
        self.language = language
        self.state = state


class MetadataEntity(msrest.serialization.Model):
    """The metadata entity contract.

    :param id: The resource Id of the metadata entity.
    :type id: str
    :param type: The type of the metadata entity.
    :type type: str
    :param name: The name of the metadata entity.
    :type name: str
    :param display_name: The display name.
    :type display_name: str
    :param depends_on: The list of keys on which this entity depends on.
    :type depends_on: list[str]
    :param applicable_scenarios: The list of scenarios applicable to this metadata entity.
    :type applicable_scenarios: list[str or ~azure.mgmt.advisor.models.Scenario]
    :param supported_values: The list of supported values.
    :type supported_values: list[~azure.mgmt.advisor.models.MetadataSupportedValueDetail]
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'depends_on': {'key': 'properties.dependsOn', 'type': '[str]'},
        'applicable_scenarios': {'key': 'properties.applicableScenarios', 'type': '[str]'},
        'supported_values': {'key': 'properties.supportedValues', 'type': '[MetadataSupportedValueDetail]'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        type: Optional[str] = None,
        name: Optional[str] = None,
        display_name: Optional[str] = None,
        depends_on: Optional[List[str]] = None,
        applicable_scenarios: Optional[List[Union[str, "Scenario"]]] = None,
        supported_values: Optional[List["MetadataSupportedValueDetail"]] = None,
        **kwargs
    ):
        super(MetadataEntity, self).__init__(**kwargs)
        self.id = id
        self.type = type
        self.name = name
        self.display_name = display_name
        self.depends_on = depends_on
        self.applicable_scenarios = applicable_scenarios
        self.supported_values = supported_values


class MetadataEntityListResult(msrest.serialization.Model):
    """The list of metadata entities.

    :param value: The list of metadata entities.
    :type value: list[~azure.mgmt.advisor.models.MetadataEntity]
    :param next_link: The link used to get the next page of metadata.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[MetadataEntity]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["MetadataEntity"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(MetadataEntityListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class MetadataSupportedValueDetail(msrest.serialization.Model):
    """The metadata supported value detail.

    :param id: The id.
    :type id: str
    :param display_name: The display name.
    :type display_name: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'display_name': {'key': 'displayName', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        display_name: Optional[str] = None,
        **kwargs
    ):
        super(MetadataSupportedValueDetail, self).__init__(**kwargs)
        self.id = id
        self.display_name = display_name


class OperationDisplayInfo(msrest.serialization.Model):
    """The operation supported by Advisor.

    :param description: The description of the operation.
    :type description: str
    :param operation: The action that users can perform, based on their permission level.
    :type operation: str
    :param provider: Service provider: Microsoft Advisor.
    :type provider: str
    :param resource: Resource on which the operation is performed.
    :type resource: str
    """

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        description: Optional[str] = None,
        operation: Optional[str] = None,
        provider: Optional[str] = None,
        resource: Optional[str] = None,
        **kwargs
    ):
        super(OperationDisplayInfo, self).__init__(**kwargs)
        self.description = description
        self.operation = operation
        self.provider = provider
        self.resource = resource


class OperationEntity(msrest.serialization.Model):
    """The operation supported by Advisor.

    :param name: Operation name: {provider}/{resource}/{operation}.
    :type name: str
    :param display: The operation supported by Advisor.
    :type display: ~azure.mgmt.advisor.models.OperationDisplayInfo
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplayInfo'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        display: Optional["OperationDisplayInfo"] = None,
        **kwargs
    ):
        super(OperationEntity, self).__init__(**kwargs)
        self.name = name
        self.display = display


class OperationEntityListResult(msrest.serialization.Model):
    """The list of Advisor operations.

    :param next_link: The link used to get the next page of operations.
    :type next_link: str
    :param value: The list of operations.
    :type value: list[~azure.mgmt.advisor.models.OperationEntity]
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'value': {'key': 'value', 'type': '[OperationEntity]'},
    }

    def __init__(
        self,
        *,
        next_link: Optional[str] = None,
        value: Optional[List["OperationEntity"]] = None,
        **kwargs
    ):
        super(OperationEntityListResult, self).__init__(**kwargs)
        self.next_link = next_link
        self.value = value


class ResourceMetadata(msrest.serialization.Model):
    """Recommendation resource metadata.

    :param resource_id: Azure resource Id of the assessed resource.
    :type resource_id: str
    :param source: Source from which recommendation is generated.
    :type source: str
    :param action: The action to view resource.
    :type action: dict[str, any]
    :param singular: The singular user friendly name of resource type. eg: virtual machine.
    :type singular: str
    :param plural: The plural user friendly name of resource type. eg: virtual machines.
    :type plural: str
    """

    _attribute_map = {
        'resource_id': {'key': 'resourceId', 'type': 'str'},
        'source': {'key': 'source', 'type': 'str'},
        'action': {'key': 'action', 'type': '{object}'},
        'singular': {'key': 'singular', 'type': 'str'},
        'plural': {'key': 'plural', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        resource_id: Optional[str] = None,
        source: Optional[str] = None,
        action: Optional[Dict[str, Any]] = None,
        singular: Optional[str] = None,
        plural: Optional[str] = None,
        **kwargs
    ):
        super(ResourceMetadata, self).__init__(**kwargs)
        self.resource_id = resource_id
        self.source = source
        self.action = action
        self.singular = singular
        self.plural = plural


class ResourceRecommendationBase(Resource):
    """Advisor Recommendation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param category: The category of the recommendation. Possible values include:
     "HighAvailability", "Security", "Performance", "Cost", "OperationalExcellence".
    :type category: str or ~azure.mgmt.advisor.models.Category
    :param impact: The business impact of the recommendation. Possible values include: "High",
     "Medium", "Low".
    :type impact: str or ~azure.mgmt.advisor.models.Impact
    :param impacted_field: The resource type identified by Advisor.
    :type impacted_field: str
    :param impacted_value: The resource identified by Advisor.
    :type impacted_value: str
    :param last_updated: The most recent time that Advisor checked the validity of the
     recommendation.
    :type last_updated: ~datetime.datetime
    :param metadata: The recommendation metadata.
    :type metadata: dict[str, any]
    :param recommendation_type_id: The recommendation-type GUID.
    :type recommendation_type_id: str
    :param risk: The potential risk of not implementing the recommendation. Possible values
     include: "Error", "Warning", "None".
    :type risk: str or ~azure.mgmt.advisor.models.Risk
    :param short_description: A summary of the recommendation.
    :type short_description: ~azure.mgmt.advisor.models.ShortDescription
    :param suppression_ids: The list of snoozed and dismissed rules for the recommendation.
    :type suppression_ids: list[str]
    :param extended_properties: Extended properties.
    :type extended_properties: dict[str, str]
    :param resource_metadata: Metadata of resource that was assessed.
    :type resource_metadata: ~azure.mgmt.advisor.models.ResourceMetadata
    :param description: The detailed description of recommendation.
    :type description: str
    :param label: The label of recommendation.
    :type label: str
    :param learn_more_link: The link to learn more about recommendation and generation logic.
    :type learn_more_link: str
    :param potential_benefits: The potential benefit of implementing recommendation.
    :type potential_benefits: str
    :param actions: The list of recommended actions to implement recommendation.
    :type actions: list[dict[str, any]]
    :param remediation: The automated way to apply recommendation.
    :type remediation: dict[str, any]
    :param exposed_metadata_properties: The recommendation metadata properties exposed to customer
     to provide additional information.
    :type exposed_metadata_properties: dict[str, any]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'category': {'key': 'properties.category', 'type': 'str'},
        'impact': {'key': 'properties.impact', 'type': 'str'},
        'impacted_field': {'key': 'properties.impactedField', 'type': 'str'},
        'impacted_value': {'key': 'properties.impactedValue', 'type': 'str'},
        'last_updated': {'key': 'properties.lastUpdated', 'type': 'iso-8601'},
        'metadata': {'key': 'properties.metadata', 'type': '{object}'},
        'recommendation_type_id': {'key': 'properties.recommendationTypeId', 'type': 'str'},
        'risk': {'key': 'properties.risk', 'type': 'str'},
        'short_description': {'key': 'properties.shortDescription', 'type': 'ShortDescription'},
        'suppression_ids': {'key': 'properties.suppressionIds', 'type': '[str]'},
        'extended_properties': {'key': 'properties.extendedProperties', 'type': '{str}'},
        'resource_metadata': {'key': 'properties.resourceMetadata', 'type': 'ResourceMetadata'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'label': {'key': 'properties.label', 'type': 'str'},
        'learn_more_link': {'key': 'properties.learnMoreLink', 'type': 'str'},
        'potential_benefits': {'key': 'properties.potentialBenefits', 'type': 'str'},
        'actions': {'key': 'properties.actions', 'type': '[{object}]'},
        'remediation': {'key': 'properties.remediation', 'type': '{object}'},
        'exposed_metadata_properties': {'key': 'properties.exposedMetadataProperties', 'type': '{object}'},
    }

    def __init__(
        self,
        *,
        category: Optional[Union[str, "Category"]] = None,
        impact: Optional[Union[str, "Impact"]] = None,
        impacted_field: Optional[str] = None,
        impacted_value: Optional[str] = None,
        last_updated: Optional[datetime.datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
        recommendation_type_id: Optional[str] = None,
        risk: Optional[Union[str, "Risk"]] = None,
        short_description: Optional["ShortDescription"] = None,
        suppression_ids: Optional[List[str]] = None,
        extended_properties: Optional[Dict[str, str]] = None,
        resource_metadata: Optional["ResourceMetadata"] = None,
        description: Optional[str] = None,
        label: Optional[str] = None,
        learn_more_link: Optional[str] = None,
        potential_benefits: Optional[str] = None,
        actions: Optional[List[Dict[str, Any]]] = None,
        remediation: Optional[Dict[str, Any]] = None,
        exposed_metadata_properties: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super(ResourceRecommendationBase, self).__init__(**kwargs)
        self.category = category
        self.impact = impact
        self.impacted_field = impacted_field
        self.impacted_value = impacted_value
        self.last_updated = last_updated
        self.metadata = metadata
        self.recommendation_type_id = recommendation_type_id
        self.risk = risk
        self.short_description = short_description
        self.suppression_ids = suppression_ids
        self.extended_properties = extended_properties
        self.resource_metadata = resource_metadata
        self.description = description
        self.label = label
        self.learn_more_link = learn_more_link
        self.potential_benefits = potential_benefits
        self.actions = actions
        self.remediation = remediation
        self.exposed_metadata_properties = exposed_metadata_properties


class ResourceRecommendationBaseListResult(msrest.serialization.Model):
    """The list of Advisor recommendations.

    :param next_link: The link used to get the next page of recommendations.
    :type next_link: str
    :param value: The list of recommendations.
    :type value: list[~azure.mgmt.advisor.models.ResourceRecommendationBase]
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'value': {'key': 'value', 'type': '[ResourceRecommendationBase]'},
    }

    def __init__(
        self,
        *,
        next_link: Optional[str] = None,
        value: Optional[List["ResourceRecommendationBase"]] = None,
        **kwargs
    ):
        super(ResourceRecommendationBaseListResult, self).__init__(**kwargs)
        self.next_link = next_link
        self.value = value


class ShortDescription(msrest.serialization.Model):
    """A summary of the recommendation.

    :param problem: The issue or opportunity identified by the recommendation.
    :type problem: str
    :param solution: The remediation action suggested by the recommendation.
    :type solution: str
    """

    _attribute_map = {
        'problem': {'key': 'problem', 'type': 'str'},
        'solution': {'key': 'solution', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        problem: Optional[str] = None,
        solution: Optional[str] = None,
        **kwargs
    ):
        super(ShortDescription, self).__init__(**kwargs)
        self.problem = problem
        self.solution = solution


class SuppressionContract(Resource):
    """The details of the snoozed or dismissed rule; for example, the duration, name, and GUID associated with the rule.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param suppression_id: The GUID of the suppression.
    :type suppression_id: str
    :param ttl: The duration for which the suppression is valid.
    :type ttl: str
    :ivar expiration_time_stamp: Gets or sets the expiration time stamp.
    :vartype expiration_time_stamp: ~datetime.datetime
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'expiration_time_stamp': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'suppression_id': {'key': 'properties.suppressionId', 'type': 'str'},
        'ttl': {'key': 'properties.ttl', 'type': 'str'},
        'expiration_time_stamp': {'key': 'properties.expirationTimeStamp', 'type': 'iso-8601'},
    }

    def __init__(
        self,
        *,
        suppression_id: Optional[str] = None,
        ttl: Optional[str] = None,
        **kwargs
    ):
        super(SuppressionContract, self).__init__(**kwargs)
        self.suppression_id = suppression_id
        self.ttl = ttl
        self.expiration_time_stamp = None


class SuppressionContractListResult(msrest.serialization.Model):
    """The list of Advisor suppressions.

    :param next_link: The link used to get the next page of suppressions.
    :type next_link: str
    :param value: The list of suppressions.
    :type value: list[~azure.mgmt.advisor.models.SuppressionContract]
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'value': {'key': 'value', 'type': '[SuppressionContract]'},
    }

    def __init__(
        self,
        *,
        next_link: Optional[str] = None,
        value: Optional[List["SuppressionContract"]] = None,
        **kwargs
    ):
        super(SuppressionContractListResult, self).__init__(**kwargs)
        self.next_link = next_link
        self.value = value
