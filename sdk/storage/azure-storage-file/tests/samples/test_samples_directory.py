# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import os

try:
    import tests.settings_real as settings
except ImportError:
    import tests.settings_fake as settings

from tests.testcase import (
    StorageTestCase,
    TestMode,
    record
)

SOURCE_FILE = 'SampleSource.txt'


class TestDirectorySamples(StorageTestCase):

    connection_string = settings.CONNECTION_STRING

    def setUp(self):
        data = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit"
        with open(SOURCE_FILE, 'wb') as stream:
            stream.write(data)

        super(TestDirectorySamples, self).setUp()

    def tearDown(self):
        if os.path.isfile(SOURCE_FILE):
            try:
                os.remove(SOURCE_FILE)
            except:
                pass

        return super(TestDirectorySamples, self).tearDown()

    #--Begin File Samples-----------------------------------------------------------------

    @record
    def test_create_directory(self):
        # Instantiate the ShareClient from a connection string
        from azure.storage.file import ShareClient
        share = ShareClient.from_connection_string(self.connection_string, "dirshare")

        # Create the share
        share.create_share()

        try:
            # Get the directory client
            dir = share.get_directory_client(directory_path="mydirectory")

            # [START create_directory]
            dir.create_directory()
            # [END create_directory]

            # [START upload_file_to_directory]
            # Upload a file to the directory
            with open(SOURCE_FILE, "rb") as source:
                dir.upload_file(file_name="sample", data=source)
            # [END upload_file_to_directory]

            # [START delete_file_in_directory]
            # Delete the file in the directory
            dir.delete_file(file_name="sample")
            # [END delete_file_in_directory]

            # [START delete_directory]
            dir.delete_directory()
            # [END delete_directory]

        finally:
            # Delete the share
            share.delete_share()

    @record
    def test_create_subdirectories(self):
        # Instantiate the ShareClient from a connection string
        from azure.storage.file import ShareClient
        share = ShareClient.from_connection_string(self.connection_string, "subdirshare")

        # Create the share
        share.create_share()

        try:
            # Get the directory client
            parent_dir = share.get_directory_client(directory_path="parentdir")

            # [START create_subdirectory]
            # Create the directory
            parent_dir.create_directory()

            # Create a subdirectory
            subdir = parent_dir.create_subdirectory("subdir")
            # [END create_subdirectory]

            # Upload a file to the parent directory
            with open(SOURCE_FILE, "rb") as source:
                parent_dir.upload_file(file_name="sample", data=source)

            # Upload a file to the subdirectory
            with open(SOURCE_FILE, "rb") as source:
                subdir.upload_file(file_name="sample", data=source)

            # [START lists_directory]
            # List the directories and files under the parent directory
            my_list = list(parent_dir.list_directories_and_files())
            print(my_list)
            # [END lists_directory]

            # You must delete the file in the subdirectory before deleting the subdirectory
            subdir.delete_file("sample")
            # [START delete_subdirectory]
            parent_dir.delete_subdirectory("subdir")
            # [END delete_subdirectory]

        finally:
            # Delete the share
            share.delete_share()

    @record
    def test_get_subdirectory_client(self):
        # Instantiate the ShareClient from a connection string
        from azure.storage.file import ShareClient
        share = ShareClient.from_connection_string(self.connection_string, "dirtest")

        # Create the share
        share.create_share()

        try:
            # [START get_subdirectory_client]
            # Get a directory client and create the directory
            parent = share.get_directory_client("dir1")
            parent.create_directory()

            # Get a subdirectory client and create the subdirectory "dir1/dir2"
            subdirectory = parent.get_subdirectory_client("dir2")
            subdirectory.create_directory()
            # [END get_subdirectory_client]
        finally:
            # Delete the share
            share.delete_share()
