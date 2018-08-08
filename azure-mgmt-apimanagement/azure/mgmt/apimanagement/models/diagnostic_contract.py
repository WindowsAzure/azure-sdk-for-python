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

from .resource import Resource


class DiagnosticContract(Resource):
    """Diagnostic details.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type for API Management resource.
    :vartype type: str
    :param always_log: Specifies for what type of messages sampling settings
     should not apply. Possible values include: 'allErrors'
    :type always_log: str or ~azure.mgmt.apimanagement.models.AlwaysLog
    :param logger_id: Required. Resource Id of a target logger.
    :type logger_id: str
    :param sampling: Sampling settings for Diagnostic.
    :type sampling: ~azure.mgmt.apimanagement.models.SamplingSettings
    :param frontend: Diagnostic settings for incoming/outcoming HTTP messages
     to the Gateway.
    :type frontend:
     ~azure.mgmt.apimanagement.models.PipelineDiagnosticSettings
    :param backend: Diagnostic settings for incoming/outcoming HTTP messages
     to the Backend
    :type backend: ~azure.mgmt.apimanagement.models.PipelineDiagnosticSettings
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'logger_id': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'always_log': {'key': 'properties.alwaysLog', 'type': 'str'},
        'logger_id': {'key': 'properties.loggerId', 'type': 'str'},
        'sampling': {'key': 'properties.sampling', 'type': 'SamplingSettings'},
        'frontend': {'key': 'properties.frontend', 'type': 'PipelineDiagnosticSettings'},
        'backend': {'key': 'properties.backend', 'type': 'PipelineDiagnosticSettings'},
    }

    def __init__(self, **kwargs):
        super(DiagnosticContract, self).__init__(**kwargs)
        self.always_log = kwargs.get('always_log', None)
        self.logger_id = kwargs.get('logger_id', None)
        self.sampling = kwargs.get('sampling', None)
        self.frontend = kwargs.get('frontend', None)
        self.backend = kwargs.get('backend', None)
