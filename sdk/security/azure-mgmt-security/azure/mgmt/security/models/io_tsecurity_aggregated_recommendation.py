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


class IoTSecurityAggregatedRecommendation(Model):
    """Security Solution Recommendation Information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id
    :vartype id: str
    :ivar name: Resource name
    :vartype name: str
    :ivar type: Resource type
    :vartype type: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param recommendation_name: Name of the recommendation
    :type recommendation_name: str
    :ivar recommendation_display_name: Display name of the recommendation
     type.
    :vartype recommendation_display_name: str
    :ivar description: Description of the incident and what it means
    :vartype description: str
    :ivar recommendation_type_id: The recommendation-type GUID.
    :vartype recommendation_type_id: str
    :ivar detected_by: Name of the vendor that discovered the issue
    :vartype detected_by: str
    :ivar remediation_steps: Recommended steps for remediation
    :vartype remediation_steps: str
    :ivar reported_severity: Estimated severity of this recommendation.
     Possible values include: 'Informational', 'Low', 'Medium', 'High'
    :vartype reported_severity: str or
     ~azure.mgmt.security.models.ReportedSeverity
    :ivar healthy_devices: the number of the healthy devices within the
     solution
    :vartype healthy_devices: int
    :ivar unhealthy_device_count: the number of the unhealthy devices within
     the solution
    :vartype unhealthy_device_count: int
    :ivar log_analytics_query: query in log analytics to get the list of
     affected devices/alerts
    :vartype log_analytics_query: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'recommendation_display_name': {'readonly': True},
        'description': {'readonly': True},
        'recommendation_type_id': {'readonly': True},
        'detected_by': {'readonly': True},
        'remediation_steps': {'readonly': True},
        'reported_severity': {'readonly': True},
        'healthy_devices': {'readonly': True},
        'unhealthy_device_count': {'readonly': True},
        'log_analytics_query': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'recommendation_name': {'key': 'properties.recommendationName', 'type': 'str'},
        'recommendation_display_name': {'key': 'properties.recommendationDisplayName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'recommendation_type_id': {'key': 'properties.recommendationTypeId', 'type': 'str'},
        'detected_by': {'key': 'properties.detectedBy', 'type': 'str'},
        'remediation_steps': {'key': 'properties.remediationSteps', 'type': 'str'},
        'reported_severity': {'key': 'properties.reportedSeverity', 'type': 'str'},
        'healthy_devices': {'key': 'properties.healthyDevices', 'type': 'int'},
        'unhealthy_device_count': {'key': 'properties.unhealthyDeviceCount', 'type': 'int'},
        'log_analytics_query': {'key': 'properties.logAnalyticsQuery', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(IoTSecurityAggregatedRecommendation, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.tags = kwargs.get('tags', None)
        self.recommendation_name = kwargs.get('recommendation_name', None)
        self.recommendation_display_name = None
        self.description = None
        self.recommendation_type_id = None
        self.detected_by = None
        self.remediation_steps = None
        self.reported_severity = None
        self.healthy_devices = None
        self.unhealthy_device_count = None
        self.log_analytics_query = None
