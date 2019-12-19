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
from msrest.exceptions import HttpOperationError


class ArmErrorResponse(Model):
    """ArmErrorResponse.

    :param error:
    :type error: ~azure.mgmt.advisor.models.ARMErrorResponseBody
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ARMErrorResponseBody'},
    }

    def __init__(self, **kwargs):
        super(ArmErrorResponse, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)


class ArmErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ArmErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ArmErrorResponseException, self).__init__(deserialize, response, 'ArmErrorResponse', *args)


class ARMErrorResponseBody(Model):
    """ARM error response body.

    :param message: Gets or sets the string that describes the error in detail
     and provides debugging information.
    :type message: str
    :param code: Gets or sets the string that can be used to programmatically
     identify the error.
    :type code: str
    """

    _attribute_map = {
        'message': {'key': 'message', 'type': 'str'},
        'code': {'key': 'code', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ARMErrorResponseBody, self).__init__(**kwargs)
        self.message = kwargs.get('message', None)
        self.code = kwargs.get('code', None)


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class Resource(Model):
    """An Azure resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

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

    def __init__(self, **kwargs):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None


class ConfigData(Resource):
    """The Advisor configuration data structure.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param exclude: Exclude the resource from Advisor evaluations. Valid
     values: False (default) or True.
    :type exclude: bool
    :param low_cpu_threshold: Minimum percentage threshold for Advisor low CPU
     utilization evaluation. Valid only for subscriptions. Valid values: 5
     (default), 10, 15 or 20. Possible values include: '5', '10', '15', '20'
    :type low_cpu_threshold: str or ~azure.mgmt.advisor.models.CpuThreshold
    :param digests: Advisor digest configuration. Valid only for subscriptions
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

    def __init__(self, **kwargs):
        super(ConfigData, self).__init__(**kwargs)
        self.exclude = kwargs.get('exclude', None)
        self.low_cpu_threshold = kwargs.get('low_cpu_threshold', None)
        self.digests = kwargs.get('digests', None)


class DigestConfig(Model):
    """Advisor Digest configuration entity.

    :param action_group_resource_id: Action group resource id used by digest.
    :type action_group_resource_id: str
    :param frequency: Frequency that digest will be triggered. Value must
     conform to ISO 8601 standard and must be greater than equal to 7 day and
     less than or equal to 30 days.
    :type frequency: str
    :param categories: Categories to send digest for. If categories are not
     provided, then digest will be sent for all categories.
    :type categories: list[str or ~azure.mgmt.advisor.models.Category]
    :param language: Language for digest content body. Value must be ISO 639-1
     code for one of Azure portal supported languages. Otherwise, it will be
     converted into one. Default value is English (en).
    :type language: str
    """

    _attribute_map = {
        'action_group_resource_id': {'key': 'actionGroupResourceId', 'type': 'str'},
        'frequency': {'key': 'frequency', 'type': 'str'},
        'categories': {'key': 'categories', 'type': '[str]'},
        'language': {'key': 'language', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(DigestConfig, self).__init__(**kwargs)
        self.action_group_resource_id = kwargs.get('action_group_resource_id', None)
        self.frequency = kwargs.get('frequency', None)
        self.categories = kwargs.get('categories', None)
        self.language = kwargs.get('language', None)


class MetadataEntity(Model):
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
    :param applicable_scenarios: The list of scenarios applicable to this
     metadata entity.
    :type applicable_scenarios: list[str or
     ~azure.mgmt.advisor.models.Scenario]
    :param supported_values: The list of supported values.
    :type supported_values:
     list[~azure.mgmt.advisor.models.MetadataSupportedValueDetail]
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

    def __init__(self, **kwargs):
        super(MetadataEntity, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.type = kwargs.get('type', None)
        self.name = kwargs.get('name', None)
        self.display_name = kwargs.get('display_name', None)
        self.depends_on = kwargs.get('depends_on', None)
        self.applicable_scenarios = kwargs.get('applicable_scenarios', None)
        self.supported_values = kwargs.get('supported_values', None)


class MetadataSupportedValueDetail(Model):
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

    def __init__(self, **kwargs):
        super(MetadataSupportedValueDetail, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.display_name = kwargs.get('display_name', None)


class OperationDisplayInfo(Model):
    """The operation supported by Advisor.

    :param description: The description of the operation.
    :type description: str
    :param operation: The action that users can perform, based on their
     permission level.
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

    def __init__(self, **kwargs):
        super(OperationDisplayInfo, self).__init__(**kwargs)
        self.description = kwargs.get('description', None)
        self.operation = kwargs.get('operation', None)
        self.provider = kwargs.get('provider', None)
        self.resource = kwargs.get('resource', None)


class OperationEntity(Model):
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

    def __init__(self, **kwargs):
        super(OperationEntity, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.display = kwargs.get('display', None)


class ResourceRecommendationBase(Resource):
    """Advisor Recommendation.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The resource ID.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param category: The category of the recommendation. Possible values
     include: 'HighAvailability', 'Security', 'Performance', 'Cost',
     'OperationalExcellence'
    :type category: str or ~azure.mgmt.advisor.models.Category
    :param impact: The business impact of the recommendation. Possible values
     include: 'High', 'Medium', 'Low'
    :type impact: str or ~azure.mgmt.advisor.models.Impact
    :param impacted_field: The resource type identified by Advisor.
    :type impacted_field: str
    :param impacted_value: The resource identified by Advisor.
    :type impacted_value: str
    :param last_updated: The most recent time that Advisor checked the
     validity of the recommendation.
    :type last_updated: datetime
    :param metadata: The recommendation metadata.
    :type metadata: dict[str, object]
    :param recommendation_type_id: The recommendation-type GUID.
    :type recommendation_type_id: str
    :param risk: The potential risk of not implementing the recommendation.
     Possible values include: 'Error', 'Warning', 'None'
    :type risk: str or ~azure.mgmt.advisor.models.Risk
    :param short_description: A summary of the recommendation.
    :type short_description: ~azure.mgmt.advisor.models.ShortDescription
    :param suppression_ids: The list of snoozed and dismissed rules for the
     recommendation.
    :type suppression_ids: list[str]
    :param extended_properties: Extended properties
    :type extended_properties: dict[str, str]
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
    }

    def __init__(self, **kwargs):
        super(ResourceRecommendationBase, self).__init__(**kwargs)
        self.category = kwargs.get('category', None)
        self.impact = kwargs.get('impact', None)
        self.impacted_field = kwargs.get('impacted_field', None)
        self.impacted_value = kwargs.get('impacted_value', None)
        self.last_updated = kwargs.get('last_updated', None)
        self.metadata = kwargs.get('metadata', None)
        self.recommendation_type_id = kwargs.get('recommendation_type_id', None)
        self.risk = kwargs.get('risk', None)
        self.short_description = kwargs.get('short_description', None)
        self.suppression_ids = kwargs.get('suppression_ids', None)
        self.extended_properties = kwargs.get('extended_properties', None)


class ShortDescription(Model):
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

    def __init__(self, **kwargs):
        super(ShortDescription, self).__init__(**kwargs)
        self.problem = kwargs.get('problem', None)
        self.solution = kwargs.get('solution', None)


class SuppressionContract(Resource):
    """The details of the snoozed or dismissed rule; for example, the duration,
    name, and GUID associated with the rule.

    Variables are only populated by the server, and will be ignored when
    sending a request.

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
        'suppression_id': {'key': 'properties.suppressionId', 'type': 'str'},
        'ttl': {'key': 'properties.ttl', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(SuppressionContract, self).__init__(**kwargs)
        self.suppression_id = kwargs.get('suppression_id', None)
        self.ttl = kwargs.get('ttl', None)
