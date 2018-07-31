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


class ApplicationUpgradeDescription(Model):
    """Describes the parameters for an application upgrade. Note that upgrade
    description replaces the existing application description. This means that
    if the parameters are not specified, the existing parameters on the
    applications will be overwritten with the empty parameters list. This would
    result in the application using the default value of the parameters from
    the application manifest. If you do not want to change any existing
    parameter values, please get the application parameters first using the
    GetApplicationInfo query and then supply those values as Parameters in this
    ApplicationUpgradeDescription.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. The name of the target application, including the
     'fabric:' URI scheme.
    :type name: str
    :param target_application_type_version: Required. The target application
     type version (found in the application manifest) for the application
     upgrade.
    :type target_application_type_version: str
    :param parameters: Required. List of application parameters with
     overridden values from their default values specified in the application
     manifest.
    :type parameters: list[~azure.servicefabric.models.ApplicationParameter]
    :param upgrade_kind: Required. The kind of upgrade out of the following
     possible values. Possible values include: 'Invalid', 'Rolling'. Default
     value: "Rolling" .
    :type upgrade_kind: str or ~azure.servicefabric.models.UpgradeKind
    :param rolling_upgrade_mode: The mode used to monitor health during a
     rolling upgrade. The values are UnmonitoredAuto, UnmonitoredManual, and
     Monitored. Possible values include: 'Invalid', 'UnmonitoredAuto',
     'UnmonitoredManual', 'Monitored'. Default value: "UnmonitoredAuto" .
    :type rolling_upgrade_mode: str or ~azure.servicefabric.models.UpgradeMode
    :param upgrade_replica_set_check_timeout_in_seconds: The maximum amount of
     time to block processing of an upgrade domain and prevent loss of
     availability when there are unexpected issues. When this timeout expires,
     processing of the upgrade domain will proceed regardless of availability
     loss issues. The timeout is reset at the start of each upgrade domain.
     Valid values are between 0 and 42949672925 inclusive. (unsigned 32-bit
     integer).
    :type upgrade_replica_set_check_timeout_in_seconds: long
    :param force_restart: If true, then processes are forcefully restarted
     during upgrade even when the code version has not changed (the upgrade
     only changes configuration or data).
    :type force_restart: bool
    :param monitoring_policy: Describes the parameters for monitoring an
     upgrade in Monitored mode.
    :type monitoring_policy:
     ~azure.servicefabric.models.MonitoringPolicyDescription
    :param application_health_policy: Defines a health policy used to evaluate
     the health of an application or one of its children entities.
    :type application_health_policy:
     ~azure.servicefabric.models.ApplicationHealthPolicy
    """

    _validation = {
        'name': {'required': True},
        'target_application_type_version': {'required': True},
        'parameters': {'required': True},
        'upgrade_kind': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'Name', 'type': 'str'},
        'target_application_type_version': {'key': 'TargetApplicationTypeVersion', 'type': 'str'},
        'parameters': {'key': 'Parameters', 'type': '[ApplicationParameter]'},
        'upgrade_kind': {'key': 'UpgradeKind', 'type': 'str'},
        'rolling_upgrade_mode': {'key': 'RollingUpgradeMode', 'type': 'str'},
        'upgrade_replica_set_check_timeout_in_seconds': {'key': 'UpgradeReplicaSetCheckTimeoutInSeconds', 'type': 'long'},
        'force_restart': {'key': 'ForceRestart', 'type': 'bool'},
        'monitoring_policy': {'key': 'MonitoringPolicy', 'type': 'MonitoringPolicyDescription'},
        'application_health_policy': {'key': 'ApplicationHealthPolicy', 'type': 'ApplicationHealthPolicy'},
    }

    def __init__(self, **kwargs):
        super(ApplicationUpgradeDescription, self).__init__(**kwargs)
        self.name = kwargs.get('name', None)
        self.target_application_type_version = kwargs.get('target_application_type_version', None)
        self.parameters = kwargs.get('parameters', None)
        self.upgrade_kind = kwargs.get('upgrade_kind', "Rolling")
        self.rolling_upgrade_mode = kwargs.get('rolling_upgrade_mode', "UnmonitoredAuto")
        self.upgrade_replica_set_check_timeout_in_seconds = kwargs.get('upgrade_replica_set_check_timeout_in_seconds', None)
        self.force_restart = kwargs.get('force_restart', None)
        self.monitoring_policy = kwargs.get('monitoring_policy', None)
        self.application_health_policy = kwargs.get('application_health_policy', None)
