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


class UpgradeOperationHistoricalStatusInfoProperties(Model):
    """Describes each OS upgrade on the Virtual Machine Scale Set.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar running_status: Information about the overall status of the upgrade
     operation.
    :vartype running_status:
     ~azure.mgmt.compute.v2018_06_01.models.UpgradeOperationHistoryStatus
    :ivar progress: Counts of the VM's in each state.
    :vartype progress:
     ~azure.mgmt.compute.v2018_06_01.models.RollingUpgradeProgressInfo
    :ivar error: Error Details for this upgrade if there are any.
    :vartype error: ~azure.mgmt.compute.v2018_06_01.models.ApiError
    :ivar started_by: Invoker of the Upgrade Operation. Possible values
     include: 'Unknown', 'User', 'Platform'
    :vartype started_by: str or
     ~azure.mgmt.compute.v2018_06_01.models.UpgradeOperationInvoker
    :ivar target_image_reference: Image Reference details
    :vartype target_image_reference:
     ~azure.mgmt.compute.v2018_06_01.models.ImageReference
    :ivar rollback_info: Information about OS rollback if performed
    :vartype rollback_info:
     ~azure.mgmt.compute.v2018_06_01.models.RollbackStatusInfo
    """

    _validation = {
        'running_status': {'readonly': True},
        'progress': {'readonly': True},
        'error': {'readonly': True},
        'started_by': {'readonly': True},
        'target_image_reference': {'readonly': True},
        'rollback_info': {'readonly': True},
    }

    _attribute_map = {
        'running_status': {'key': 'runningStatus', 'type': 'UpgradeOperationHistoryStatus'},
        'progress': {'key': 'progress', 'type': 'RollingUpgradeProgressInfo'},
        'error': {'key': 'error', 'type': 'ApiError'},
        'started_by': {'key': 'startedBy', 'type': 'UpgradeOperationInvoker'},
        'target_image_reference': {'key': 'targetImageReference', 'type': 'ImageReference'},
        'rollback_info': {'key': 'rollbackInfo', 'type': 'RollbackStatusInfo'},
    }

    def __init__(self, **kwargs) -> None:
        super(UpgradeOperationHistoricalStatusInfoProperties, self).__init__(**kwargs)
        self.running_status = None
        self.progress = None
        self.error = None
        self.started_by = None
        self.target_image_reference = None
        self.rollback_info = None
