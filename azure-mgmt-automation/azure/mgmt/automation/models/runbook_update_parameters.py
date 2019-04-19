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


class RunbookUpdateParameters(Model):
    """The parameters supplied to the update runbook operation.

    :param description: Gets or sets the description of the runbook.
    :type description: str
    :param log_verbose: Gets or sets verbose log option.
    :type log_verbose: bool
    :param log_progress: Gets or sets progress log option.
    :type log_progress: bool
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

    _attribute_map = {
        'description': {'key': 'properties.description', 'type': 'str'},
        'log_verbose': {'key': 'properties.logVerbose', 'type': 'bool'},
        'log_progress': {'key': 'properties.logProgress', 'type': 'bool'},
        'log_activity_trace': {'key': 'properties.logActivityTrace', 'type': 'int'},
        'name': {'key': 'name', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, **kwargs):
        super(RunbookUpdateParameters, self).__init__(**kwargs)
        self.description = kwargs.get('description', None)
        self.log_verbose = kwargs.get('log_verbose', None)
        self.log_progress = kwargs.get('log_progress', None)
        self.log_activity_trace = kwargs.get('log_activity_trace', None)
        self.name = kwargs.get('name', None)
        self.location = kwargs.get('location', None)
        self.tags = kwargs.get('tags', None)
