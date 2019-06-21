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

try:
    from .resource_py3 import Resource
    from .activity_log_alert_leaf_condition_py3 import ActivityLogAlertLeafCondition
    from .activity_log_alert_all_of_condition_py3 import ActivityLogAlertAllOfCondition
    from .activity_log_alert_action_group_py3 import ActivityLogAlertActionGroup
    from .activity_log_alert_action_list_py3 import ActivityLogAlertActionList
    from .activity_log_alert_resource_py3 import ActivityLogAlertResource
    from .error_response_py3 import ErrorResponse, ErrorResponseException
    from .activity_log_alert_resource_patch_py3 import ActivityLogAlertResourcePatch
except (SyntaxError, ImportError):
    from .resource import Resource
    from .activity_log_alert_leaf_condition import ActivityLogAlertLeafCondition
    from .activity_log_alert_all_of_condition import ActivityLogAlertAllOfCondition
    from .activity_log_alert_action_group import ActivityLogAlertActionGroup
    from .activity_log_alert_action_list import ActivityLogAlertActionList
    from .activity_log_alert_resource import ActivityLogAlertResource
    from .error_response import ErrorResponse, ErrorResponseException
    from .activity_log_alert_resource_patch import ActivityLogAlertResourcePatch
from .activity_log_alert_resource_paged import ActivityLogAlertResourcePaged

__all__ = [
    'Resource',
    'ActivityLogAlertLeafCondition',
    'ActivityLogAlertAllOfCondition',
    'ActivityLogAlertActionGroup',
    'ActivityLogAlertActionList',
    'ActivityLogAlertResource',
    'ErrorResponse', 'ErrorResponseException',
    'ActivityLogAlertResourcePatch',
    'ActivityLogAlertResourcePaged',
]
