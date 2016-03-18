# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.service_client import ServiceClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from .operations.workflows_operations import WorkflowsOperations
from .operations.workflow_versions_operations import WorkflowVersionsOperations
from .operations.workflow_access_keys_operations import WorkflowAccessKeysOperations
from .operations.workflow_triggers_operations import WorkflowTriggersOperations
from .operations.workflow_trigger_histories_operations import WorkflowTriggerHistoriesOperations
from .operations.workflow_runs_operations import WorkflowRunsOperations
from .operations.workflow_run_actions_operations import WorkflowRunActionsOperations
from . import models


class LogicManagementClientConfiguration(AzureConfiguration):
    """Configuration for LogicManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Gets Azure subscription credentials.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: The subscription id.
    :type subscription_id: str
    :param api_version: The API version.
    :type api_version: str
    :param accept_language: Gets or sets the preferred language for the
     response.
    :type accept_language: str
    :param long_running_operation_retry_timeout: Gets or sets the retry
     timeout in seconds for Long Running Operations. Default value is 30.
    :type long_running_operation_retry_timeout: int
    :param generate_client_request_id: When set to true a unique
     x-ms-client-request-id value is generated and included in each request.
     Default is true.
    :type generate_client_request_id: bool
    :param str base_url: Service URL
    :param str filepath: Existing config
    """

    def __init__(
            self, credentials, subscription_id, api_version='2015-02-01-preview', accept_language='en-US', long_running_operation_retry_timeout=30, generate_client_request_id=True, base_url=None, filepath=None):

        if credentials is None:
            raise ValueError('credentials must not be None.')
        if subscription_id is None:
            raise ValueError('subscription_id must not be None.')
        if not base_url:
            base_url = 'https://management.azure.com'

        super(LogicManagementClientConfiguration, self).__init__(base_url, filepath)

        self.add_user_agent('logicmanagementclient/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id
        self.api_version = api_version
        self.accept_language = accept_language
        self.long_running_operation_retry_timeout = long_running_operation_retry_timeout
        self.generate_client_request_id = generate_client_request_id


class LogicManagementClient(object):
    """LogicManagementClient

    :param config: Configuration for client.
    :type config: LogicManagementClientConfiguration

    :ivar workflows: Workflows operations
    :vartype workflows: .operations.WorkflowsOperations
    :ivar workflow_versions: WorkflowVersions operations
    :vartype workflow_versions: .operations.WorkflowVersionsOperations
    :ivar workflow_access_keys: WorkflowAccessKeys operations
    :vartype workflow_access_keys: .operations.WorkflowAccessKeysOperations
    :ivar workflow_triggers: WorkflowTriggers operations
    :vartype workflow_triggers: .operations.WorkflowTriggersOperations
    :ivar workflow_trigger_histories: WorkflowTriggerHistories operations
    :vartype workflow_trigger_histories: .operations.WorkflowTriggerHistoriesOperations
    :ivar workflow_runs: WorkflowRuns operations
    :vartype workflow_runs: .operations.WorkflowRunsOperations
    :ivar workflow_run_actions: WorkflowRunActions operations
    :vartype workflow_run_actions: .operations.WorkflowRunActionsOperations
    """

    def __init__(self, config):

        self._client = ServiceClient(config.credentials, config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer()
        self._deserialize = Deserializer(client_models)

        self.config = config
        self.workflows = WorkflowsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workflow_versions = WorkflowVersionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workflow_access_keys = WorkflowAccessKeysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workflow_triggers = WorkflowTriggersOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workflow_trigger_histories = WorkflowTriggerHistoriesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workflow_runs = WorkflowRunsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.workflow_run_actions = WorkflowRunActionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
