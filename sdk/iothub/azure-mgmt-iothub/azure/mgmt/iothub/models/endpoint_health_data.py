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


class EndpointHealthData(Model):
    """The health data for an endpoint.

    :param endpoint_id: Id of the endpoint
    :type endpoint_id: str
    :param health_status: Health statuses have following meanings. The
     'healthy' status shows that the endpoint is accepting messages as
     expected. The 'unhealthy' status shows that the endpoint is not accepting
     messages as expected and IoT Hub is retrying to send data to this
     endpoint. The status of an unhealthy endpoint will be updated to healthy
     when IoT Hub has established an eventually consistent state of health. The
     'dead' status shows that the endpoint is not accepting messages, after IoT
     Hub retried sending messages for the retrial period. See IoT Hub metrics
     to identify errors and monitor issues with endpoints. The 'unknown' status
     shows that the IoT Hub has not established a connection with the endpoint.
     No messages have been delivered to or rejected from this endpoint.
     Possible values include: 'unknown', 'healthy', 'unhealthy', 'dead'
    :type health_status: str or ~azure.mgmt.iothub.models.EndpointHealthStatus
    """

    _attribute_map = {
        'endpoint_id': {'key': 'endpointId', 'type': 'str'},
        'health_status': {'key': 'healthStatus', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(EndpointHealthData, self).__init__(**kwargs)
        self.endpoint_id = kwargs.get('endpoint_id', None)
        self.health_status = kwargs.get('health_status', None)
