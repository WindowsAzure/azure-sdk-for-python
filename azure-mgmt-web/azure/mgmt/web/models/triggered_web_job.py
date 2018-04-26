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

from .proxy_only_resource import ProxyOnlyResource


class TriggeredWebJob(ProxyOnlyResource):
    """Triggered Web Job Information.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource Name.
    :vartype name: str
    :param kind: Kind of resource.
    :type kind: str
    :ivar type: Resource type.
    :vartype type: str
    :param latest_run: Latest job run information.
    :type latest_run: ~azure.mgmt.web.models.TriggeredJobRun
    :param history_url: History URL.
    :type history_url: str
    :param scheduler_logs_url: Scheduler Logs URL.
    :type scheduler_logs_url: str
    :ivar triggered_web_job_name: Job name. Used as job identifier in ARM
     resource URI.
    :vartype triggered_web_job_name: str
    :param run_command: Run command.
    :type run_command: str
    :param url: Job URL.
    :type url: str
    :param extra_info_url: Extra Info URL.
    :type extra_info_url: str
    :param job_type: Job type. Possible values include: 'Continuous',
     'Triggered'
    :type job_type: str or ~azure.mgmt.web.models.WebJobType
    :param error: Error information.
    :type error: str
    :param using_sdk: Using SDK?
    :type using_sdk: bool
    :param settings: Job settings.
    :type settings: dict[str, object]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'triggered_web_job_name': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'latest_run': {'key': 'properties.latestRun', 'type': 'TriggeredJobRun'},
        'history_url': {'key': 'properties.historyUrl', 'type': 'str'},
        'scheduler_logs_url': {'key': 'properties.schedulerLogsUrl', 'type': 'str'},
        'triggered_web_job_name': {'key': 'properties.name', 'type': 'str'},
        'run_command': {'key': 'properties.runCommand', 'type': 'str'},
        'url': {'key': 'properties.url', 'type': 'str'},
        'extra_info_url': {'key': 'properties.extraInfoUrl', 'type': 'str'},
        'job_type': {'key': 'properties.jobType', 'type': 'WebJobType'},
        'error': {'key': 'properties.error', 'type': 'str'},
        'using_sdk': {'key': 'properties.usingSdk', 'type': 'bool'},
        'settings': {'key': 'properties.settings', 'type': '{object}'},
    }

    def __init__(self, **kwargs):
        super(TriggeredWebJob, self).__init__(**kwargs)
        self.latest_run = kwargs.get('latest_run', None)
        self.history_url = kwargs.get('history_url', None)
        self.scheduler_logs_url = kwargs.get('scheduler_logs_url', None)
        self.triggered_web_job_name = None
        self.run_command = kwargs.get('run_command', None)
        self.url = kwargs.get('url', None)
        self.extra_info_url = kwargs.get('extra_info_url', None)
        self.job_type = kwargs.get('job_type', None)
        self.error = kwargs.get('error', None)
        self.using_sdk = kwargs.get('using_sdk', None)
        self.settings = kwargs.get('settings', None)
