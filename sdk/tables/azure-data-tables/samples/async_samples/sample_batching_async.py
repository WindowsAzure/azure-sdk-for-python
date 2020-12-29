# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: sample_batching.py

DESCRIPTION:
    These samples demonstrate how to use the batching API to perform multiple
    operations within a single request

USAGE:
    python sample_batching.py

    Set the environment variables with your own values before running the sample:
    1) AZURE_STORAGE_CONNECTION_STRING - the connection string to your storage account
"""


from datetime import datetime, timedelta
import os
import asyncio
from dotenv import find_dotenv, load_dotenv


class CreateClients(object):

    def __init__(self):
        load_dotenv(find_dotenv())
        # self.connection_string = os.getenv("AZURE_TABLES_CONNECTION_STRING")
        self.access_key = os.getenv("TABLES_PRIMARY_STORAGE_ACCOUNT_KEY")
        self.endpoint = os.getenv("TABLES_STORAGE_ENDPOINT_SUFFIX")
        self.account_name = os.getenv("TABLES_STORAGE_ACCOUNT_NAME")
        self.account_url = "{}.table.{}".format(self.account_name, self.endpoint)
        self.connection_string = "DefaultEndpointsProtocol=https;AccountName={};AccountKey={};EndpointSuffix={}".format(
            self.account_name,
            self.access_key,
            self.endpoint
        )

    async def sample_batching(self):
        # Instantiate a TableServiceClient using a connection string
        entity1 = {
            'PartitionKey': 'pk001',
            'RowKey': 'rk001',
            'Value': 4,
            'day': "Monday",
            'float': 4.003
        }
        entity2 = {
            'PartitionKey': 'pk001',
            'RowKey': 'rk002',
            'Value': 4,
            'day': "Tuesday",
            'float': 4.003
        }
        entity3 = {
            'PartitionKey': 'pk001',
            'RowKey': 'rk003',
            'Value': 4,
            'day': "Wednesday",
            'float': 4.003
        }
        entity4 = {
            'PartitionKey': 'pk001',
            'RowKey': 'rk004',
            'Value': 4,
            'day': "Thursday",
            'float': 4.003
        }

        # [START batching]
        from azure.data.tables.aio import TableClient
        from azure.data.tables import UpdateMode, BatchErrorException
        from azure.core.exceptions import ResourceExistsError
        table_client = TableClient.from_connection_string(conn_str=self.connection_string, table_name="tableName")

        try:
            await table_client.create_table()
            print("Created table")
        except ResourceExistsError:
            print("Table already exists")

        await table_client.create_entity(entity2)
        await table_client.create_entity(entity3)
        await table_client.create_entity(entity4)

        batch = table_client.create_batch()
        batch.create_entity(entity1)
        batch.delete_entity(entity2)
        batch.upsert_entity(entity3)
        batch.update_entity(entity4, mode=UpdateMode.REPLACE)
        try:
            await table_client.send_batch(batch)
        except BatchErrorException as e:
            print("There was an error with the batch operation")
            print("Error: {}".format(e))
        # [END batching]


async def main():
    sample = CreateClients()
    await sample.sample_batching()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
