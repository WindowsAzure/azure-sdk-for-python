# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import os
from azure.monitor.query import LogQueryClient
from azure.identity import ClientSecretCredential


credential  = ClientSecretCredential(
        client_id = os.environ['AZURE_CLIENT_ID'],
        client_secret = os.environ['AZURE_CLIENT_SECRET'],
        tenant_id = os.environ['AZURE_TENANT_ID']
    )

client = LogQueryClient(credential)

response = client.query("d2d0e126-fa1e-4b0a-b647-250cdd471e68", "AppRequests")

for item in response.tables:
    print(item.rows,len(item.rows))
    print("\n\n\n\n\n\n")
