# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class Action(msrest.serialization.Model):
    """Actions to invoke when the alert fires.

    :param action_group_id: Action Group resource Id to invoke when the alert fires.
    :type action_group_id: str
    :param web_hook_properties: The properties of a webhook object.
    :type web_hook_properties: dict[str, str]
    """

    _attribute_map = {
        'action_group_id': {'key': 'actionGroupId', 'type': 'str'},
        'web_hook_properties': {'key': 'webHookProperties', 'type': '{str}'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Action, self).__init__(**kwargs)
        self.action_group_id = kwargs.get('action_group_id', None)
        self.web_hook_properties = kwargs.get('web_hook_properties', None)


class Condition(msrest.serialization.Model):
    """A condition of the scheduled query rule.

    All required parameters must be populated in order to send to Azure.

    :param query: Log query alert.
    :type query: str
    :param time_aggregation: Required. Aggregation type. Possible values include: "Count",
     "Average", "Minimum", "Maximum", "Total".
    :type time_aggregation: str or ~$(python-base-
     namespace).v2020_05_01_preview.models.TimeAggregation
    :param metric_measure_column: The column containing the metric measure number.
    :type metric_measure_column: str
    :param resource_id_column: The column containing the resource id. The content of the column
     must be a uri formatted as resource id.
    :type resource_id_column: str
    :param dimensions: List of Dimensions conditions.
    :type dimensions: list[~$(python-base-namespace).v2020_05_01_preview.models.Dimension]
    :param operator: Required. The criteria operator. Possible values include: "Equals",
     "GreaterThan", "GreaterThanOrEqual", "LessThan", "LessThanOrEqual".
    :type operator: str or ~$(python-base-namespace).v2020_05_01_preview.models.ConditionOperator
    :param threshold: Required. the criteria threshold value that activates the alert.
    :type threshold: float
    :param failing_periods: The minimum number of violations required within the selected lookback
     time window required to raise an alert.
    :type failing_periods: ~$(python-base-
     namespace).v2020_05_01_preview.models.ConditionFailingPeriods
    """

    _validation = {
        'time_aggregation': {'required': True},
        'operator': {'required': True},
        'threshold': {'required': True},
    }

    _attribute_map = {
        'query': {'key': 'query', 'type': 'str'},
        'time_aggregation': {'key': 'timeAggregation', 'type': 'str'},
        'metric_measure_column': {'key': 'metricMeasureColumn', 'type': 'str'},
        'resource_id_column': {'key': 'resourceIdColumn', 'type': 'str'},
        'dimensions': {'key': 'dimensions', 'type': '[Dimension]'},
        'operator': {'key': 'operator', 'type': 'str'},
        'threshold': {'key': 'threshold', 'type': 'float'},
        'failing_periods': {'key': 'failingPeriods', 'type': 'ConditionFailingPeriods'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Condition, self).__init__(**kwargs)
        self.query = kwargs.get('query', None)
        self.time_aggregation = kwargs['time_aggregation']
        self.metric_measure_column = kwargs.get('metric_measure_column', None)
        self.resource_id_column = kwargs.get('resource_id_column', None)
        self.dimensions = kwargs.get('dimensions', None)
        self.operator = kwargs['operator']
        self.threshold = kwargs['threshold']
        self.failing_periods = kwargs.get('failing_periods', None)


class ConditionFailingPeriods(msrest.serialization.Model):
    """The minimum number of violations required within the selected lookback time window required to raise an alert.

    :param number_of_evaluation_periods: The number of aggregated lookback points. The lookback
     time window is calculated based on the aggregation granularity (windowSize) and the selected
     number of aggregated points. Default value is 1.
    :type number_of_evaluation_periods: long
    :param min_failing_periods_to_alert: The number of violations to trigger an alert. Should be
     smaller or equal to numberOfEvaluationPeriods. Default value is 1.
    :type min_failing_periods_to_alert: long
    """

    _attribute_map = {
        'number_of_evaluation_periods': {'key': 'numberOfEvaluationPeriods', 'type': 'long'},
        'min_failing_periods_to_alert': {'key': 'minFailingPeriodsToAlert', 'type': 'long'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ConditionFailingPeriods, self).__init__(**kwargs)
        self.number_of_evaluation_periods = kwargs.get('number_of_evaluation_periods', 1)
        self.min_failing_periods_to_alert = kwargs.get('min_failing_periods_to_alert', 1)


class Dimension(msrest.serialization.Model):
    """Dimension splitting and filtering definition.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Name of the dimension.
    :type name: str
    :param operator: Required. Operator for dimension values. Possible values include: "Include",
     "Exclude".
    :type operator: str or ~$(python-base-namespace).v2020_05_01_preview.models.DimensionOperator
    :param values: Required. List of dimension values.
    :type values: list[str]
    """

    _validation = {
        'name': {'required': True},
        'operator': {'required': True},
        'values': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'operator': {'key': 'operator', 'type': 'str'},
        'values': {'key': 'values', 'type': '[str]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(Dimension, self).__init__(**kwargs)
        self.name = kwargs['name']
        self.operator = kwargs['operator']
        self.values = kwargs['values']


class ErrorAdditionalInfo(msrest.serialization.Model):
    """The resource management error additional info.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar type: The additional info type.
    :vartype type: str
    :ivar info: The additional info.
    :vartype info: object
    """

    _validation = {
        'type': {'readonly': True},
        'info': {'readonly': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
        'info': {'key': 'info', 'type': 'object'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorAdditionalInfo, self).__init__(**kwargs)
        self.type = None
        self.info = None


class ErrorContract(msrest.serialization.Model):
    """Describes the format of Error response.

    :param error: The error details.
    :type error: ~$(python-base-namespace).v2020_05_01_preview.models.ErrorResponse
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponse'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorContract, self).__init__(**kwargs)
        self.error = kwargs.get('error', None)


class ErrorResponse(msrest.serialization.Model):
    """Common error response for all Azure Resource Manager APIs to return error details for failed operations. (This also follows the OData error response format.).

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar code: The error code.
    :vartype code: str
    :ivar message: The error message.
    :vartype message: str
    :ivar target: The error target.
    :vartype target: str
    :ivar details: The error details.
    :vartype details: list[~$(python-base-namespace).v2020_05_01_preview.models.ErrorResponse]
    :ivar additional_info: The error additional info.
    :vartype additional_info: list[~$(python-base-
     namespace).v2020_05_01_preview.models.ErrorAdditionalInfo]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'target': {'readonly': True},
        'details': {'readonly': True},
        'additional_info': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorResponse]'},
        'additional_info': {'key': 'additionalInfo', 'type': '[ErrorAdditionalInfo]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.target = None
        self.details = None
        self.additional_info = None


class Resource(msrest.serialization.Model):
    """Common fields that are returned in the response for all Azure Resource Manager resources.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
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


class ScheduledQueryRuleCriteria(msrest.serialization.Model):
    """The rule criteria that defines the conditions of the scheduled query rule.

    :param all_of: A list of conditions to evaluate against the specified scopes.
    :type all_of: list[~$(python-base-namespace).v2020_05_01_preview.models.Condition]
    """

    _attribute_map = {
        'all_of': {'key': 'allOf', 'type': '[Condition]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ScheduledQueryRuleCriteria, self).__init__(**kwargs)
        self.all_of = kwargs.get('all_of', None)


class TrackedResource(Resource):
    """The resource model definition for an Azure Resource Manager tracked top level resource which has 'tags' and a 'location'.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives.
    :type location: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(TrackedResource, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.location = kwargs['location']


class ScheduledQueryRuleResource(TrackedResource):
    """The scheduled query rule resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Fully qualified resource ID for the resource. Ex -
     /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/{resourceProviderNamespace}/{resourceType}/{resourceName}.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource. E.g. "Microsoft.Compute/virtualMachines" or
     "Microsoft.Storage/storageAccounts".
    :vartype type: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param location: Required. The geo-location where the resource lives.
    :type location: str
    :param description: The description of the scheduled query rule.
    :type description: str
    :param severity: Severity of the alert. Should be an integer between [0-4]. Value of 0 is
     severest. Possible values include: 0, 1, 2, 3, 4.
    :type severity: str or ~$(python-base-namespace).v2020_05_01_preview.models.AlertSeverity
    :param enabled: The flag which indicates whether this scheduled query rule is enabled. Value
     should be true or false.
    :type enabled: bool
    :param scopes: The list of resource id's that this scheduled query rule is scoped to.
    :type scopes: list[str]
    :param evaluation_frequency: How often the scheduled query rule is evaluated represented in ISO
     8601 duration format.
    :type evaluation_frequency: ~datetime.timedelta
    :param window_size: The period of time (in ISO 8601 duration format) on which the Alert query
     will be executed (bin size).
    :type window_size: ~datetime.timedelta
    :param target_resource_types: List of resource type of the target resource(s) on which the
     alert is created/updated. For example if the scope is a resource group and targetResourceTypes
     is Microsoft.Compute/virtualMachines, then a different alert will be fired for each virtual
     machine in the resource group which meet the alert criteria.
    :type target_resource_types: list[str]
    :param criteria: The rule criteria that defines the conditions of the scheduled query rule.
    :type criteria: ~$(python-base-namespace).v2020_05_01_preview.models.ScheduledQueryRuleCriteria
    :param mute_actions_duration: Mute actions for the chosen period of time (in ISO 8601 duration
     format) after the alert is fired.
    :type mute_actions_duration: ~datetime.timedelta
    :param actions:
    :type actions: list[~$(python-base-namespace).v2020_05_01_preview.models.Action]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'severity': {'key': 'properties.severity', 'type': 'float'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'scopes': {'key': 'properties.scopes', 'type': '[str]'},
        'evaluation_frequency': {'key': 'properties.evaluationFrequency', 'type': 'duration'},
        'window_size': {'key': 'properties.windowSize', 'type': 'duration'},
        'target_resource_types': {'key': 'properties.targetResourceTypes', 'type': '[str]'},
        'criteria': {'key': 'properties.criteria', 'type': 'ScheduledQueryRuleCriteria'},
        'mute_actions_duration': {'key': 'properties.muteActionsDuration', 'type': 'duration'},
        'actions': {'key': 'properties.actions', 'type': '[Action]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ScheduledQueryRuleResource, self).__init__(**kwargs)
        self.description = kwargs.get('description', None)
        self.severity = kwargs.get('severity', None)
        self.enabled = kwargs.get('enabled', None)
        self.scopes = kwargs.get('scopes', None)
        self.evaluation_frequency = kwargs.get('evaluation_frequency', None)
        self.window_size = kwargs.get('window_size', None)
        self.target_resource_types = kwargs.get('target_resource_types', None)
        self.criteria = kwargs.get('criteria', None)
        self.mute_actions_duration = kwargs.get('mute_actions_duration', None)
        self.actions = kwargs.get('actions', None)


class ScheduledQueryRuleResourceCollection(msrest.serialization.Model):
    """Represents a collection of scheduled query rule resources.

    :param value: The values for the scheduled query rule resources.
    :type value: list[~$(python-base-
     namespace).v2020_05_01_preview.models.ScheduledQueryRuleResource]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ScheduledQueryRuleResource]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ScheduledQueryRuleResourceCollection, self).__init__(**kwargs)
        self.value = kwargs.get('value', None)


class ScheduledQueryRuleResourcePatch(msrest.serialization.Model):
    """The scheduled query rule resource for patch operations.

    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param description: The description of the scheduled query rule.
    :type description: str
    :param severity: Severity of the alert. Should be an integer between [0-4]. Value of 0 is
     severest. Possible values include: 0, 1, 2, 3, 4.
    :type severity: str or ~$(python-base-namespace).v2020_05_01_preview.models.AlertSeverity
    :param enabled: The flag which indicates whether this scheduled query rule is enabled. Value
     should be true or false.
    :type enabled: bool
    :param scopes: The list of resource id's that this scheduled query rule is scoped to.
    :type scopes: list[str]
    :param evaluation_frequency: How often the scheduled query rule is evaluated represented in ISO
     8601 duration format.
    :type evaluation_frequency: ~datetime.timedelta
    :param window_size: The period of time (in ISO 8601 duration format) on which the Alert query
     will be executed (bin size).
    :type window_size: ~datetime.timedelta
    :param target_resource_types: List of resource type of the target resource(s) on which the
     alert is created/updated. For example if the scope is a resource group and targetResourceTypes
     is Microsoft.Compute/virtualMachines, then a different alert will be fired for each virtual
     machine in the resource group which meet the alert criteria.
    :type target_resource_types: list[str]
    :param criteria: The rule criteria that defines the conditions of the scheduled query rule.
    :type criteria: ~$(python-base-namespace).v2020_05_01_preview.models.ScheduledQueryRuleCriteria
    :param mute_actions_duration: Mute actions for the chosen period of time (in ISO 8601 duration
     format) after the alert is fired.
    :type mute_actions_duration: ~datetime.timedelta
    :param actions:
    :type actions: list[~$(python-base-namespace).v2020_05_01_preview.models.Action]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'severity': {'key': 'properties.severity', 'type': 'float'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'scopes': {'key': 'properties.scopes', 'type': '[str]'},
        'evaluation_frequency': {'key': 'properties.evaluationFrequency', 'type': 'duration'},
        'window_size': {'key': 'properties.windowSize', 'type': 'duration'},
        'target_resource_types': {'key': 'properties.targetResourceTypes', 'type': '[str]'},
        'criteria': {'key': 'properties.criteria', 'type': 'ScheduledQueryRuleCriteria'},
        'mute_actions_duration': {'key': 'properties.muteActionsDuration', 'type': 'duration'},
        'actions': {'key': 'properties.actions', 'type': '[Action]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ScheduledQueryRuleResourcePatch, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.description = kwargs.get('description', None)
        self.severity = kwargs.get('severity', None)
        self.enabled = kwargs.get('enabled', None)
        self.scopes = kwargs.get('scopes', None)
        self.evaluation_frequency = kwargs.get('evaluation_frequency', None)
        self.window_size = kwargs.get('window_size', None)
        self.target_resource_types = kwargs.get('target_resource_types', None)
        self.criteria = kwargs.get('criteria', None)
        self.mute_actions_duration = kwargs.get('mute_actions_duration', None)
        self.actions = kwargs.get('actions', None)
