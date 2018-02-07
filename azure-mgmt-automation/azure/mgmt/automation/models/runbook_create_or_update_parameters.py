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


class RunbookCreateOrUpdateParameters(Model):
    """The parameters supplied to the create or update runbook operation.

    :param log_verbose: Gets or sets verbose log option.
    :type log_verbose: bool
    :param log_progress: Gets or sets progress log option.
    :type log_progress: bool
    :param runbook_type: Gets or sets the type of the runbook. Possible values
     include: 'Script', 'Graph', 'PowerShellWorkflow', 'PowerShell',
     'GraphPowerShellWorkflow', 'GraphPowerShell'
    :type runbook_type: str or ~azure.mgmt.automation.models.RunbookTypeEnum
    :param draft: Gets or sets the draft runbook properties.
    :type draft: ~azure.mgmt.automation.models.RunbookDraft
    :param publish_content_link: Gets or sets the published runbook content
     link.
    :type publish_content_link: ~azure.mgmt.automation.models.ContentLink
    :param description: Gets or sets the description of the runbook.
    :type description: str
    :param log_activity_trace: Gets or sets the activity-level tracing options
     of the runbook.
    :type log_activity_trace: int
    :param name: Gets or sets the name of the resource.
    :type name: str
    :param location: Gets or sets the location of the resource.
    :type location: str
    :param tags: Gets or sets the tags attached to the resource.
    :type tags: dict[str, str]
    """

    _validation = {
        'runbook_type': {'required': True},
    }

    _attribute_map = {
        'log_verbose': {'key': 'properties.logVerbose', 'type': 'bool'},
        'log_progress': {'key': 'properties.logProgress', 'type': 'bool'},
        'runbook_type': {'key': 'properties.runbookType', 'type': 'str'},
        'draft': {'key': 'properties.draft', 'type': 'RunbookDraft'},
        'publish_content_link': {'key': 'properties.publishContentLink', 'type': 'ContentLink'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'log_activity_trace': {'key': 'properties.logActivityTrace', 'type': 'int'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, runbook_type, log_verbose=None, log_progress=None, draft=None, publish_content_link=None, description=None, log_activity_trace=None, name=None, location=None, tags=None):
        super(RunbookCreateOrUpdateParameters, self).__init__()
        self.log_verbose = log_verbose
        self.log_progress = log_progress
        self.runbook_type = runbook_type
        self.draft = draft
        self.publish_content_link = publish_content_link
        self.description = description
        self.log_activity_trace = log_activity_trace
        self.name = name
        self.location = location
        self.tags = tags
