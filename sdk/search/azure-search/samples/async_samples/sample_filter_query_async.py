# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: sample_authentication.py
DESCRIPTION:
    This sample demonstrates how to authenticate with the Azure Congnitive Search
    service with an API key. See more details about authentication here:
    https://docs.microsoft.com/en-us/azure/search/search-security-api-keys
USAGE:
    python sample_authentication.py

    Set the environment variables with your own values before running the sample:
    1) AZURE_SEARCH_SERVICE_NAME - the name of your Azure Cognitive Search service
    2) AZURE_SEARCH_INDEX_NAME - the name of your search index (e.g. "hotels-sample-index")
    3) AZURE_SEARCH_API_KEY - your search API key
"""

import os
import asyncio


service_name = os.getenv("AZURE_SEARCH_SERVICE_NAME")
index_name = os.getenv("AZURE_SEARCH_INDEX_NAME")
key = os.getenv("AZURE_SEARCH_API_KEY")

async def filter_query():
    # [START filter_query_async]
    from azure.search.aio import SearchIndexClient
    from azure.search import SearchApiKeyCredential, SearchQuery

    search_client = SearchIndexClient(service_name, index_name, SearchApiKeyCredential(key))

    query = SearchQuery(search_text="WiFi")
    query.filter("Address/StateProvince eq 'FL' and Address/Country eq 'USA'")
    query.select("HotelName", "Rating")
    query.order_by("Rating desc")

    results = await search_client.search(query=query)

    print("Florida hotels containing 'WiFi', sorted by Rating:")
    async for result in results:
        print("    Name: {} (rating {})".format(result["HotelName"], result["Rating"]))

    await search_client.close()
    # [END filter_query_async]

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(filter_query())