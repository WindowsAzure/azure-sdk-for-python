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


class ExitOptions(Model):
    """Specifies how the Batch service responds to a particular exit condition.

    :param job_action: An action to take on the job containing the task, if
     the task completes with the given exit condition and the job's
     onTaskFailed property is 'performExitOptionsJobAction'. The default is
     none for exit code 0 and terminate for all other exit conditions. If the
     job's onTaskFailed property is noAction, then specifying this property
     returns an error and the add task request fails with an invalid property
     value error; if you are calling the REST API directly, the HTTP status
     code is 400 (Bad Request). Possible values include: 'none', 'disable',
     'terminate'
    :type job_action: str or ~azure.batch.models.JobAction
    :param dependency_action: An action that the Batch service performs on
     tasks that depend on this task. The default is 'satisfy' for exit code 0,
     and 'block' for all other exit conditions. If the job's
     usesTaskDependencies property is set to false, then specifying the
     dependencyAction property returns an error and the add task request fails
     with an invalid property value error; if you are calling the REST API
     directly, the HTTP status code is 400  (Bad Request). Possible values
     include: 'satisfy', 'block'
    :type dependency_action: str or ~azure.batch.models.DependencyAction
    """

    _attribute_map = {
        'job_action': {'key': 'jobAction', 'type': 'JobAction'},
        'dependency_action': {'key': 'dependencyAction', 'type': 'DependencyAction'},
    }

    def __init__(self, *, job_action=None, dependency_action=None, **kwargs) -> None:
        super(ExitOptions, self).__init__(**kwargs)
        self.job_action = job_action
        self.dependency_action = dependency_action
