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


class DeploymentOperationProperties(Model):
    """Deployment operation properties.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar provisioning_state: The state of the provisioning.
    :vartype provisioning_state: str
    :ivar timestamp: The date and time of the operation.
    :vartype timestamp: datetime
    :ivar service_request_id: Deployment operation service request id.
    :vartype service_request_id: str
    :ivar status_code: Operation status code.
    :vartype status_code: str
    :ivar status_message: Operation status message.
    :vartype status_message: object
    :ivar target_resource: The target resource.
    :vartype target_resource:
     ~azure.mgmt.resource.resources.v2016_09_01.models.TargetResource
    :ivar request: The HTTP request message.
    :vartype request:
     ~azure.mgmt.resource.resources.v2016_09_01.models.HttpMessage
    :ivar response: The HTTP response message.
    :vartype response:
     ~azure.mgmt.resource.resources.v2016_09_01.models.HttpMessage
    """

    _validation = {
        'provisioning_state': {'readonly': True},
        'timestamp': {'readonly': True},
        'service_request_id': {'readonly': True},
        'status_code': {'readonly': True},
        'status_message': {'readonly': True},
        'target_resource': {'readonly': True},
        'request': {'readonly': True},
        'response': {'readonly': True},
    }

    _attribute_map = {
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'timestamp': {'key': 'timestamp', 'type': 'iso-8601'},
        'service_request_id': {'key': 'serviceRequestId', 'type': 'str'},
        'status_code': {'key': 'statusCode', 'type': 'str'},
        'status_message': {'key': 'statusMessage', 'type': 'object'},
        'target_resource': {'key': 'targetResource', 'type': 'TargetResource'},
        'request': {'key': 'request', 'type': 'HttpMessage'},
        'response': {'key': 'response', 'type': 'HttpMessage'},
    }

    def __init__(self, **kwargs):
        super(DeploymentOperationProperties, self).__init__(**kwargs)
        self.provisioning_state = None
        self.timestamp = None
        self.service_request_id = None
        self.status_code = None
        self.status_message = None
        self.target_resource = None
        self.request = None
        self.response = None
