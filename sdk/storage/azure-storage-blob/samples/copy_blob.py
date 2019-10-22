# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: copy_blob.py
DESCRIPTION:
    This sample demos how to copy a blob from a URL.
USAGE: python copy_blob.py
"""

import os
import sys
import time
from azure.storage.blob import BlobServiceClient

def main():
    try:
        CONNECTION_STRING = os.environ['AZURE_STORAGE_CONNECTION_STRING']

    except KeyError:
        print("AZURE_STORAGE_CONNECTION_STRING must be set.")
        sys.exit(1)

    blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
    source_blob = "http://www.gutenberg.org/files/59466/59466-0.txt"
    copied_blob = blob_service_client.get_blob_client("mycontainer", '59466-0.txt')
    print("Copy started")
    copied_blob.start_copy_from_url(source_blob)
    for i in range(10):
        props = copied_blob.get_blob_properties()
        status = props.copy.status
        print("Copy status: " + status)
        if status == "success":
            print("Copy finished")
            break
        time.sleep(10)

if __name__ == "__main__":
    main()
