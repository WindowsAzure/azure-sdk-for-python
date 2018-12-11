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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from .operations.application_operations import ApplicationOperations
from .operations.pool_operations import PoolOperations
from .operations.account_operations import AccountOperations
from .operations.job_operations import JobOperations
from .operations.certificate_operations import CertificateOperations
from .operations.file_operations import FileOperations
from .operations.job_schedule_operations import JobScheduleOperations
from .operations.task_operations import TaskOperations
from .operations.compute_node_operations import ComputeNodeOperations
from . import models


class BatchServiceClientConfiguration(AzureConfiguration):
    """Configuration for BatchServiceClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param batch_url: The base URL for all Azure Batch service requests.
    :type batch_url: str
    """

    def __init__(
            self, credentials, batch_url):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if batch_url is None:
            raise ValueError("Parameter 'batch_url' must not be None.")
        base_url = '{batchUrl}'

        super(BatchServiceClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-batch/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.batch_url = batch_url


class BatchServiceClient(SDKClient):
    """A client for issuing REST requests to the Azure Batch service.

    :ivar config: Configuration for client.
    :vartype config: BatchServiceClientConfiguration

    :ivar application: Application operations
    :vartype application: azure.batch.operations.ApplicationOperations
    :ivar pool: Pool operations
    :vartype pool: azure.batch.operations.PoolOperations
    :ivar account: Account operations
    :vartype account: azure.batch.operations.AccountOperations
    :ivar job: Job operations
    :vartype job: azure.batch.operations.JobOperations
    :ivar certificate: Certificate operations
    :vartype certificate: azure.batch.operations.CertificateOperations
    :ivar file: File operations
    :vartype file: azure.batch.operations.FileOperations
    :ivar job_schedule: JobSchedule operations
    :vartype job_schedule: azure.batch.operations.JobScheduleOperations
    :ivar task: Task operations
    :vartype task: azure.batch.operations.TaskOperations
    :ivar compute_node: ComputeNode operations
    :vartype compute_node: azure.batch.operations.ComputeNodeOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param batch_url: The base URL for all Azure Batch service requests.
    :type batch_url: str
    """

    def __init__(
            self, credentials, batch_url):

        self.config = BatchServiceClientConfiguration(credentials, batch_url)
        super(BatchServiceClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-12-01.8.0'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.application = ApplicationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.pool = PoolOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.account = AccountOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job = JobOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.certificate = CertificateOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.file = FileOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.job_schedule = JobScheduleOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.task = TaskOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.compute_node = ComputeNodeOperations(
            self._client, self.config, self._serialize, self._deserialize)
