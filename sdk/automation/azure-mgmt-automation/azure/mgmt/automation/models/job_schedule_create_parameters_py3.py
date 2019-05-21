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


class JobScheduleCreateParameters(Model):
    """The parameters supplied to the create job schedule operation.

    All required parameters must be populated in order to send to Azure.

    :param schedule: Required. Gets or sets the schedule.
    :type schedule: ~azure.mgmt.automation.models.ScheduleAssociationProperty
    :param runbook: Required. Gets or sets the runbook.
    :type runbook: ~azure.mgmt.automation.models.RunbookAssociationProperty
    :param run_on: Gets or sets the hybrid worker group that the scheduled job
     should run on.
    :type run_on: str
    :param parameters: Gets or sets a list of job properties.
    :type parameters: dict[str, str]
    """

    _validation = {
        'schedule': {'required': True},
        'runbook': {'required': True},
    }

    _attribute_map = {
        'schedule': {'key': 'properties.schedule', 'type': 'ScheduleAssociationProperty'},
        'runbook': {'key': 'properties.runbook', 'type': 'RunbookAssociationProperty'},
        'run_on': {'key': 'properties.runOn', 'type': 'str'},
        'parameters': {'key': 'properties.parameters', 'type': '{str}'},
    }

    def __init__(self, *, schedule, runbook, run_on: str=None, parameters=None, **kwargs) -> None:
        super(JobScheduleCreateParameters, self).__init__(**kwargs)
        self.schedule = schedule
        self.runbook = runbook
        self.run_on = run_on
        self.parameters = parameters
