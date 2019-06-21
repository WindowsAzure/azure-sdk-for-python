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


class LogSettings(Model):
    """Part of MultiTenantDiagnosticSettings. Specifies the settings for a
    particular log.

    All required parameters must be populated in order to send to Azure.

    :param category: Name of a Diagnostic Log category for a resource type
     this setting is applied to. To obtain the list of Diagnostic Log
     categories for a resource, first perform a GET diagnostic settings
     operation.
    :type category: str
    :param enabled: Required. a value indicating whether this log is enabled.
    :type enabled: bool
    :param retention_policy: the retention policy for this log.
    :type retention_policy:
     ~azure.mgmt.monitor.v2015_07_01.models.RetentionPolicy
    """

    _validation = {
        'enabled': {'required': True},
    }

    _attribute_map = {
        'category': {'key': 'category', 'type': 'str'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'retention_policy': {'key': 'retentionPolicy', 'type': 'RetentionPolicy'},
    }

    def __init__(self, *, enabled: bool, category: str=None, retention_policy=None, **kwargs) -> None:
        super(LogSettings, self).__init__(**kwargs)
        self.category = category
        self.enabled = enabled
        self.retention_policy = retention_policy
