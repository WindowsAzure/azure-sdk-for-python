# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import os
from azure.monitor.query import MetricsClient
from azure.identity import ClientSecretCredential

credential  = ClientSecretCredential(
        client_id = os.environ['AZURE_CLIENT_ID'],
        client_secret = os.environ['AZURE_CLIENT_SECRET'],
        tenant_id = os.environ['AZURE_TENANT_ID']
    )

client = MetricsClient(credential)

metrics_uri = os.environ['METRICS_RESOURCE_URI']
response = client.list_metric_definitions(metrics_uri, metric_namespace='microsoft.eventgrid/topics')

for item in response:
    pass
