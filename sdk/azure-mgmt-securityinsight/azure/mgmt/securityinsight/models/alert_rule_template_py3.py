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


class AlertRuleTemplate(Model):
    """Alert rule template.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: FusionAlertRuleTemplate,
    MicrosoftSecurityIncidentCreationAlertRuleTemplate,
    ScheduledAlertRuleTemplate

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'kind': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'Fusion': 'FusionAlertRuleTemplate', 'MicrosoftSecurityIncidentCreation': 'MicrosoftSecurityIncidentCreationAlertRuleTemplate', 'Scheduled': 'ScheduledAlertRuleTemplate'}
    }

    def __init__(self, **kwargs) -> None:
        super(AlertRuleTemplate, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.kind = None
