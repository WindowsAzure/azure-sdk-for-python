# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import TYPE_CHECKING

from azure.mgmt.core import ARMPipelineClient
from msrest import Deserializer, Serializer

if TYPE_CHECKING:
    # pylint: disable=unused-import,ungrouped-imports
    from typing import Any, Optional

    from azure.core.credentials import TokenCredential
    from azure.core.pipeline.transport import HttpRequest, HttpResponse

from ._configuration import TestBaseConfiguration
from .operations import SkusOperations
from .operations import TestBaseAccountsOperations
from .operations import UsageOperations
from .operations import AvailableOSOperations
from .operations import FlightingRingsOperations
from .operations import TestTypesOperations
from .operations import PackagesOperations
from .operations import TestSummariesOperations
from .operations import TestResultsOperations
from .operations import OSUpdatesOperations
from .operations import FavoriteProcessesOperations
from .operations import AnalysisResultsOperations
from .operations import EmailEventsOperations
from .operations import CustomerEventsOperations
from .operations import Operations
from . import models


class TestBase(object):
    """Test Base.

    :ivar skus: SkusOperations operations
    :vartype skus: test_base.operations.SkusOperations
    :ivar test_base_accounts: TestBaseAccountsOperations operations
    :vartype test_base_accounts: test_base.operations.TestBaseAccountsOperations
    :ivar usage: UsageOperations operations
    :vartype usage: test_base.operations.UsageOperations
    :ivar available_os: AvailableOSOperations operations
    :vartype available_os: test_base.operations.AvailableOSOperations
    :ivar flighting_rings: FlightingRingsOperations operations
    :vartype flighting_rings: test_base.operations.FlightingRingsOperations
    :ivar test_types: TestTypesOperations operations
    :vartype test_types: test_base.operations.TestTypesOperations
    :ivar packages: PackagesOperations operations
    :vartype packages: test_base.operations.PackagesOperations
    :ivar test_summaries: TestSummariesOperations operations
    :vartype test_summaries: test_base.operations.TestSummariesOperations
    :ivar test_results: TestResultsOperations operations
    :vartype test_results: test_base.operations.TestResultsOperations
    :ivar os_updates: OSUpdatesOperations operations
    :vartype os_updates: test_base.operations.OSUpdatesOperations
    :ivar favorite_processes: FavoriteProcessesOperations operations
    :vartype favorite_processes: test_base.operations.FavoriteProcessesOperations
    :ivar analysis_results: AnalysisResultsOperations operations
    :vartype analysis_results: test_base.operations.AnalysisResultsOperations
    :ivar email_events: EmailEventsOperations operations
    :vartype email_events: test_base.operations.EmailEventsOperations
    :ivar customer_events: CustomerEventsOperations operations
    :vartype customer_events: test_base.operations.CustomerEventsOperations
    :ivar operations: Operations operations
    :vartype operations: test_base.operations.Operations
    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: The Azure subscription ID. This is a GUID-formatted string.
    :type subscription_id: str
    :param str base_url: Service URL
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        base_url=None,  # type: Optional[str]
        **kwargs  # type: Any
    ):
        # type: (...) -> None
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = TestBaseConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self._serialize = Serializer(client_models)
        self._serialize.client_side_validation = False
        self._deserialize = Deserializer(client_models)

        self.skus = SkusOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.test_base_accounts = TestBaseAccountsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.usage = UsageOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.available_os = AvailableOSOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.flighting_rings = FlightingRingsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.test_types = TestTypesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.packages = PackagesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.test_summaries = TestSummariesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.test_results = TestResultsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.os_updates = OSUpdatesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.favorite_processes = FavoriteProcessesOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.analysis_results = AnalysisResultsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.email_events = EmailEventsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.customer_events = CustomerEventsOperations(
            self._client, self._config, self._serialize, self._deserialize)
        self.operations = Operations(
            self._client, self._config, self._serialize, self._deserialize)

    def _send_request(self, http_request, **kwargs):
        # type: (HttpRequest, Any) -> HttpResponse
        """Runs the network request through the client's chained policies.

        :param http_request: The network request you want to make. Required.
        :type http_request: ~azure.core.pipeline.transport.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to True.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.pipeline.transport.HttpResponse
        """
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self._config.subscription_id", self._config.subscription_id, 'str'),
        }
        http_request.url = self._client.format_url(http_request.url, **path_format_arguments)
        stream = kwargs.pop("stream", True)
        pipeline_response = self._client._pipeline.run(http_request, stream=stream, **kwargs)
        return pipeline_response.http_response

    def close(self):
        # type: () -> None
        self._client.close()

    def __enter__(self):
        # type: () -> TestBase
        self._client.__enter__()
        return self

    def __exit__(self, *exc_details):
        # type: (Any) -> None
        self._client.__exit__(*exc_details)
