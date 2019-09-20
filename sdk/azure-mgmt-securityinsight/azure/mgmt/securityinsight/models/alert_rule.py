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


class AlertRule(Model):
    """Alert rule.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: FusionAlertRule,
    MicrosoftSecurityIncidentCreationAlertRule, ScheduledAlertRule

    All required parameters must be populated in order to send to Azure.

    :param etag: Etag of the azure resource
    :type etag: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    """

    _validation = {
        'kind': {'required': True},
    }

    _attribute_map = {
        'etag': {'key': 'etag', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
    }

    _subtype_map = {
        'kind': {'Fusion': 'FusionAlertRule', 'MicrosoftSecurityIncidentCreation': 'MicrosoftSecurityIncidentCreationAlertRule', 'Scheduled': 'ScheduledAlertRule'}
    }

    def __init__(self, **kwargs):
        super(AlertRule, self).__init__(**kwargs)
        self.etag = kwargs.get('etag', None)
        self.kind = None
