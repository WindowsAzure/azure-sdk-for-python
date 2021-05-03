# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os

from azure_devtools.perfstress_tests import PerfStressTest

from azure.ai.metricsadvisor import MetricsAdvisorClient as SyncClient, MetricsAdvisorKeyCredential
from azure.ai.metricsadvisor.aio import MetricsAdvisorClient as AsyncClient


class ListRootCausesTest(PerfStressTest):
    def __init__(self, arguments):
        super().__init__(arguments)
        service_endpoint = os.getenv("AZURE_METRICS_ADVISOR_ENDPOINT")
        subscription_key = os.getenv("AZURE_METRICS_ADVISOR_SUBSCRIPTION_KEY")
        api_key = os.getenv("AZURE_METRICS_ADVISOR_API_KEY")
        self.anomaly_detection_configuration_id = os.getenv("AZURE_METRICS_ADVISOR_ANOMALY_DETECTION_CONFIGURATION_ID")
        self.incident_id = os.getenv("AZURE_METRICS_ADVISOR_INCIDENT_ID")
        self.service_client = SyncClient(service_endpoint, MetricsAdvisorKeyCredential(subscription_key, api_key))
        self.async_service_client = AsyncClient(service_endpoint, MetricsAdvisorKeyCredential(subscription_key, api_key))

    async def close(self):
        await self.async_service_client.close()
        await super().close()

    def run_sync(self):
        results = self.service_client.list_incident_root_causes(
            detection_configuration_id=self.anomaly_detection_configuration_id,
            incident_id=self.incident_id,
        )
        for _ in results:
            pass

    async def run_async(self):
        results = self.async_service_client.list_incident_root_causes(
            detection_configuration_id=self.anomaly_detection_configuration_id,
            incident_id=self.incident_id,
        )
        async for _ in results:
            pass
