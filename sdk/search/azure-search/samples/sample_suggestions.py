# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: sample_suggestions.py
DESCRIPTION:
    This sample demonstrates how to authenticate with the Azure Congnitive Search
    service with an API key. See more details about authentication here:
    https://docs.microsoft.com/en-us/azure/search/search-security-api-keys
USAGE:
    python sample_suggestions.py

    Set the environment variables with your own values before running the sample:
    1) AZURE_SEARCH_SERVICE_NAME - the name of your Azure Cognitive Search service
    2) AZURE_SEARCH_INDEX_NAME - the name of your search index (e.g. "hotels-sample-index")
    3) AZURE_SEARCH_API_KEY - your search API key
"""

import os

service_name = os.getenv("AZURE_SEARCH_SERVICE_NAME")
index_name = os.getenv("AZURE_SEARCH_INDEX_NAME")
key = os.getenv("AZURE_SEARCH_API_KEY")

def suggest_query():
    # [START suggest_query]
    from azure.search import SearchApiKeyCredential, SearchIndexClient, SuggestQuery

    search_client = SearchIndexClient(service_name, index_name, SearchApiKeyCredential(key))

    query = SuggestQuery(search_text="coffee", suggester_name="sg")

    results = search_client.suggest(query=query)

    print("Search suggestions for 'coffee'")
    for result in results:
        hotel = search_client.get_document(key=result["HotelId"])
        print("    Text: {} for Hotel: {}".format(repr(result["text"]), hotel["HotelName"]))
    # [END suggest_query]

if __name__ == '__main__':
    suggest_query()
