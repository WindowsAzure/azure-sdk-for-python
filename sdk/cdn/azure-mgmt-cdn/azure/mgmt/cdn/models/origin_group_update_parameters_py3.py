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


class OriginGroupUpdateParameters(Model):
    """Origin group properties needed for origin group creation or update.

    :param health_probe_settings: Health probe settings to the origin that is
     used to determine the health of the origin.
    :type health_probe_settings: ~azure.mgmt.cdn.models.HealthProbeParameters
    :param origins: The source of the content being delivered via CDN within
     given origin group.
    :type origins: list[~azure.mgmt.cdn.models.ResourceReference]
    :param traffic_restoration_time_to_healed_or_new_endpoints_in_minutes:
     Time in minutes to shift the traffic to the endpoint gradually when an
     unhealthy endpoint comes healthy or a new endpoint is added. Default is 10
     mins. This property is currently not supported.
    :type traffic_restoration_time_to_healed_or_new_endpoints_in_minutes: int
    :param response_based_origin_error_detection_settings: The JSON object
     that contains the properties to determine origin health using real
     requests/responses. This property is currently not supported.
    :type response_based_origin_error_detection_settings:
     ~azure.mgmt.cdn.models.ResponseBasedOriginErrorDetectionParameters
    """

    _validation = {
        'traffic_restoration_time_to_healed_or_new_endpoints_in_minutes': {'maximum': 50, 'minimum': 0},
    }

    _attribute_map = {
        'health_probe_settings': {'key': 'properties.healthProbeSettings', 'type': 'HealthProbeParameters'},
        'origins': {'key': 'properties.origins', 'type': '[ResourceReference]'},
        'traffic_restoration_time_to_healed_or_new_endpoints_in_minutes': {'key': 'properties.trafficRestorationTimeToHealedOrNewEndpointsInMinutes', 'type': 'int'},
        'response_based_origin_error_detection_settings': {'key': 'properties.responseBasedOriginErrorDetectionSettings', 'type': 'ResponseBasedOriginErrorDetectionParameters'},
    }

    def __init__(self, *, health_probe_settings=None, origins=None, traffic_restoration_time_to_healed_or_new_endpoints_in_minutes: int=None, response_based_origin_error_detection_settings=None, **kwargs) -> None:
        super(OriginGroupUpdateParameters, self).__init__(**kwargs)
        self.health_probe_settings = health_probe_settings
        self.origins = origins
        self.traffic_restoration_time_to_healed_or_new_endpoints_in_minutes = traffic_restoration_time_to_healed_or_new_endpoints_in_minutes
        self.response_based_origin_error_detection_settings = response_based_origin_error_detection_settings
