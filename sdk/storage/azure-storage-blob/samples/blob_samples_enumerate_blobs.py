# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: enumerate_blobs.py
DESCRIPTION:
    This sample demos how to enumerate a container and print all blobs.
USAGE: python enumerate_blobs.py
"""

from __future__ import print_function
import os
import sys
from azure.storage.blob import ContainerClient

def main():
    try:
        CONNECTION_STRING = os.environ['AZURE_STORAGE_CONNECTION_STRING']

    except KeyError:
        print("AZURE_STORAGE_CONNECTION_STRING must be set.")
        sys.exit(1)

    container = ContainerClient.from_connection_string(CONNECTION_STRING, container_name="mycontainer")

    blob_list = container.list_blobs()
    for blob in blob_list:
        print(blob.name + '\n')

if __name__ == "__main__":
    main()
