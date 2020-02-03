# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
import pytest
from datetime import datetime, timedelta

from azure.core.exceptions import HttpResponseError
from azure.storage.blob import (
    BlobServiceClient,
    BlobType,
    BlobBlock,
    BlobSasPermissions,
    generate_blob_sas
)
from _shared.testcase import StorageTestCase, GlobalStorageAccountPreparer

# ------------------------------------------------------------------------------
# The encryption scope are pre-created using management plane tool ArmClient.
# So we can directly use the scope in the test.
TEST_ENCRYPTION_KEY_SCOPE = "antjoscope1"
TEST_CONTAINER_ENCRYPTION_KEY_SCOPE = "containerscope"

# ------------------------------------------------------------------------------

class StorageCPKNTest(StorageTestCase):
    def _setup(self, bsc):
        self.config = bsc._config
        self.container_name = self.get_resource_name('utcontainer')

        # prep some test data so that they can be used in upload tests
        self.byte_data = self.get_random_bytes(64 * 1024)

        if self.is_live:
            bsc.create_container(self.container_name)

    def _teardown(self, bsc):
        if self.is_live:
            try:
                bsc.delete_container(self.container_name)
            except:
                pass

        return super(StorageCPKNTest, self).tearDown()

    # --Helpers-----------------------------------------------------------------

    def _get_blob_reference(self):
        return self.get_resource_name("cpk")

    def _create_block_blob(self, bsc, blob_name=None, data=None, encryption_scope=None, max_concurrency=1):
        blob_name = blob_name if blob_name else self._get_blob_reference()
        blob_client = bsc.get_blob_client(self.container_name, blob_name)
        data = data if data else b''
        resp = blob_client.upload_blob(data, encryption_scope=encryption_scope, max_concurrency=max_concurrency)
        return blob_client, resp

    def _create_append_blob(self, bsc, encryption_scope=None):
        blob_name = self._get_blob_reference()
        blob = bsc.get_blob_client(
            self.container_name,
            blob_name)
        blob.create_append_blob(encryption_scope=encryption_scope)
        return blob

    def _create_page_blob(self, bsc, encryption_scope=None):
        blob_name = self._get_blob_reference()
        blob = bsc.get_blob_client(
            self.container_name,
            blob_name)
        blob.create_page_blob(1024 * 1024, encryption_scope=encryption_scope)
        return blob

    # -- Test cases for APIs supporting CPK ----------------------------------------------

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_put_block_and_put_block_list(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        blob_client, _ = self._create_block_blob(bsc)
        blob_client.stage_block('1', b'AAA', encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)
        blob_client.stage_block('2', b'BBB', encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)
        blob_client.stage_block('3', b'CCC', encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Act
        block_list = [BlobBlock(block_id='1'), BlobBlock(block_id='2'), BlobBlock(block_id='3')]
        put_block_list_resp = blob_client.commit_block_list(block_list,
                                                            encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        self.assertIsNotNone(put_block_list_resp['etag'])
        self.assertIsNotNone(put_block_list_resp['last_modified'])
        self.assertTrue(put_block_list_resp['request_server_encrypted'])
        self.assertEqual(put_block_list_resp['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        # Act get the blob content
        blob = blob_client.download_blob()

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), b'AAABBBCCC')
        self.assertEqual(blob.properties.etag, put_block_list_resp['etag'])
        self.assertEqual(blob.properties.last_modified, put_block_list_resp['last_modified'])
        self.assertEqual(blob.properties.encryption_scope, TEST_ENCRYPTION_KEY_SCOPE)
        self._teardown(bsc)

    @pytest.mark.live_test_only
    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_create_block_blob_with_chunks(self, resource_group, location, storage_account, storage_account_key):
        # parallel operation
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        # Arrange
        #  to force the in-memory chunks to be used
        self.config.use_byte_buffer = True

        # Act
        # create_blob_from_bytes forces the in-memory chunks to be used
        blob_client, upload_response = self._create_block_blob(bsc, data=self.byte_data, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE,
                                                               max_concurrency=2)

        # Assert
        self.assertIsNotNone(upload_response['etag'])
        self.assertIsNotNone(upload_response['last_modified'])
        self.assertTrue(upload_response['request_server_encrypted'])
        self.assertEqual(upload_response['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        # Act get the blob content
        blob = blob_client.download_blob()

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), self.byte_data)
        self.assertEqual(blob.properties.etag, upload_response['etag'])
        self.assertEqual(blob.properties.last_modified, upload_response['last_modified'])
        self._teardown(bsc)

    @pytest.mark.live_test_only
    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_create_block_blob_with_sub_streams(self, resource_group, location, storage_account, storage_account_key):
        # problem with the recording framework can only run live
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)

        # Act
        # create_blob_from_bytes forces the in-memory chunks to be used
        blob_client, upload_response = self._create_block_blob(bsc, data=self.byte_data, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE,
                                                               max_concurrency=2)

        # Assert
        self.assertIsNotNone(upload_response['etag'])
        self.assertIsNotNone(upload_response['last_modified'])
        self.assertTrue(upload_response['request_server_encrypted'])
        self.assertEqual(upload_response['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        # Act get the blob content
        blob = blob_client.download_blob()

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), self.byte_data)
        self.assertEqual(blob.properties.etag, upload_response['etag'])
        self.assertEqual(blob.properties.last_modified, upload_response['last_modified'])
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_create_block_blob_with_single_chunk(self, resource_group, location, storage_account, storage_account_key):
        # Act
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        data = b'AAABBBCCC'
        # create_blob_from_bytes forces the in-memory chunks to be used
        blob_client, upload_response = self._create_block_blob(bsc, data=data, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        self.assertIsNotNone(upload_response['etag'])
        self.assertIsNotNone(upload_response['last_modified'])
        self.assertTrue(upload_response['request_server_encrypted'])

        # Act get the blob content
        blob = blob_client.download_blob()

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), data)
        self.assertEqual(blob.properties.etag, upload_response['etag'])
        self.assertEqual(blob.properties.last_modified, upload_response['last_modified'])
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_put_block_from_url_and_commit_with_cpk(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        # create source blob and get source blob url
        source_blob_name = self.get_resource_name("sourceblob")
        self.config.use_byte_buffer = True  # Make sure using chunk upload, then we can record the request
        source_blob_client, _ = self._create_block_blob(bsc, blob_name=source_blob_name, data=self.byte_data)
        source_blob_sas = generate_blob_sas(
            source_blob_client.account_name,
            source_blob_client.container_name,
            source_blob_client.blob_name,
            snapshot=source_blob_client.snapshot,
            account_key=source_blob_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(hours=1)
        )
        source_blob_url = source_blob_client.url + "?" + source_blob_sas

        # create destination blob
        self.config.use_byte_buffer = False
        destination_blob_client, _ = self._create_block_blob(bsc, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Act part 1: make put block from url calls
        destination_blob_client.stage_block_from_url(block_id=1, source_url=source_blob_url,
                                                     source_offset=0, source_length=4 * 1024,
                                                     encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)
        destination_blob_client.stage_block_from_url(block_id=2, source_url=source_blob_url,
                                                     source_offset=4 * 1024, source_length=4 * 1024,
                                                     encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert blocks
        committed, uncommitted = destination_blob_client.get_block_list('all')
        self.assertEqual(len(uncommitted), 2)
        self.assertEqual(len(committed), 0)

        # commit the blocks without cpk should fail
        block_list = [BlobBlock(block_id='1'), BlobBlock(block_id='2')]
        with self.assertRaises(HttpResponseError):
            destination_blob_client.commit_block_list(block_list)

        # Act commit the blocks with cpk should succeed
        put_block_list_resp = destination_blob_client.commit_block_list(block_list,
                                                                        encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        self.assertIsNotNone(put_block_list_resp['etag'])
        self.assertIsNotNone(put_block_list_resp['last_modified'])
        self.assertTrue(put_block_list_resp['request_server_encrypted'])

        # Act get the blob content
        blob = destination_blob_client.download_blob()

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), self.byte_data[0: 8 * 1024])
        self.assertEqual(blob.properties.etag, put_block_list_resp['etag'])
        self.assertEqual(blob.properties.last_modified, put_block_list_resp['last_modified'])
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_append_block(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        blob_client = self._create_append_blob(bsc, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Act
        for content in [b'AAA', b'BBB', b'CCC']:
            append_blob_prop = blob_client.append_block(content, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

            # Assert
            self.assertIsNotNone(append_blob_prop['etag'])
            self.assertIsNotNone(append_blob_prop['last_modified'])
            self.assertTrue(append_blob_prop['request_server_encrypted'])

        # Act get the blob content
        blob = blob_client.download_blob()

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), b'AAABBBCCC')
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_append_block_from_url(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        source_blob_name = self.get_resource_name("sourceblob")
        self.config.use_byte_buffer = True  # chunk upload
        source_blob_client, _ = self._create_block_blob(bsc, blob_name=source_blob_name, data=self.byte_data)
        source_blob_sas = generate_blob_sas(
            source_blob_client.account_name,
            source_blob_client.container_name,
            source_blob_client.blob_name,
            snapshot=source_blob_client.snapshot,
            account_key=source_blob_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(hours=1)
        )
        source_blob_url = source_blob_client.url + "?" + source_blob_sas

        self.config.use_byte_buffer = False
        destination_blob_client = self._create_append_blob(bsc, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Act
        append_blob_prop = destination_blob_client.append_block_from_url(source_blob_url,
                                                                         source_offset=0,
                                                                         source_length=4 * 1024,
                                                                         encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        self.assertIsNotNone(append_blob_prop['etag'])
        self.assertIsNotNone(append_blob_prop['last_modified'])
        self.assertTrue(append_blob_prop['request_server_encrypted'])
        self.assertEqual(append_blob_prop['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        # Act get the blob content
        blob = destination_blob_client.download_blob()

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), self.byte_data[0: 4 * 1024])
        self.assertEqual(blob.properties.encryption_scope, TEST_ENCRYPTION_KEY_SCOPE)
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_create_append_blob_with_chunks(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        blob_client = self._create_append_blob(bsc, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Act
        append_blob_prop = blob_client.upload_blob(self.byte_data,
                                                   blob_type=BlobType.AppendBlob, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        self.assertIsNotNone(append_blob_prop['etag'])
        self.assertIsNotNone(append_blob_prop['last_modified'])
        self.assertTrue(append_blob_prop['request_server_encrypted'])
        self.assertEqual(append_blob_prop['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        # Act get the blob content
        blob = blob_client.download_blob()

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), self.byte_data)
        self.assertEqual(blob.properties.encryption_scope, TEST_ENCRYPTION_KEY_SCOPE)
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_update_page(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        blob_client = self._create_page_blob(bsc, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Act
        page_blob_prop = blob_client.upload_page(self.byte_data,
                                                 offset=0,
                                                 length=len(self.byte_data),
                                                 encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        self.assertIsNotNone(page_blob_prop['etag'])
        self.assertIsNotNone(page_blob_prop['last_modified'])
        self.assertTrue(page_blob_prop['request_server_encrypted'])
        self.assertEqual(page_blob_prop['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        # Act get the blob content
        blob = blob_client.download_blob(offset=0,
                                         length=len(self.byte_data))

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), self.byte_data)
        self.assertEqual(blob.properties.encryption_scope, TEST_ENCRYPTION_KEY_SCOPE)
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_update_page_from_url(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        source_blob_name = self.get_resource_name("sourceblob")
        self.config.use_byte_buffer = True  # Make sure using chunk upload, then we can record the request
        source_blob_client, _ = self._create_block_blob(bsc, blob_name=source_blob_name, data=self.byte_data)
        source_blob_sas = generate_blob_sas(
            source_blob_client.account_name,
            source_blob_client.container_name,
            source_blob_client.blob_name,
            snapshot=source_blob_client.snapshot,
            account_key=source_blob_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(hours=1)
        )
        source_blob_url = source_blob_client.url + "?" + source_blob_sas

        self.config.use_byte_buffer = False
        blob_client = self._create_page_blob(bsc, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Act
        page_blob_prop = blob_client.upload_pages_from_url(source_blob_url,
                                                           offset=0,
                                                           length=len(self.byte_data),
                                                           source_offset=0,
                                                           encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        self.assertIsNotNone(page_blob_prop['etag'])
        self.assertIsNotNone(page_blob_prop['last_modified'])
        self.assertTrue(page_blob_prop['request_server_encrypted'])
        self.assertEqual(page_blob_prop['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        # Act get the blob content
        blob = blob_client.download_blob(offset=0,
                                         length=len(self.byte_data))

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), self.byte_data)
        self.assertEqual(blob.properties.encryption_scope, TEST_ENCRYPTION_KEY_SCOPE)
        self._teardown(bsc)

    @pytest.mark.live_test_only
    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_create_page_blob_with_chunks(self, resource_group, location, storage_account, storage_account_key):
        # Act
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        blob_client = bsc.get_blob_client(self.container_name, self._get_blob_reference())
        page_blob_prop = blob_client.upload_blob(self.byte_data,
                                                 blob_type=BlobType.PageBlob,
                                                 max_concurrency=2,
                                                 encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        self.assertIsNotNone(page_blob_prop['etag'])
        self.assertIsNotNone(page_blob_prop['last_modified'])
        self.assertTrue(page_blob_prop['request_server_encrypted'])
        self.assertEqual(page_blob_prop['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        # Act get the blob content
        blob = blob_client.download_blob()

        # Assert content was retrieved with the cpk
        self.assertEqual(blob.readall(), self.byte_data)
        self.assertEqual(blob.properties.encryption_scope, TEST_ENCRYPTION_KEY_SCOPE)
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_get_set_blob_metadata(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        blob_client, _ = self._create_block_blob(bsc, data=b'AAABBBCCC', encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Act
        blob_props = blob_client.get_blob_properties()

        # Assert
        self.assertTrue(blob_props.server_encrypted)
        self.assertEqual(blob_props['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        # Act set blob properties
        metadata = {'hello': 'world', 'number': '42', 'up': 'upval'}
        with self.assertRaises(HttpResponseError):
            blob_client.set_blob_metadata(
                metadata=metadata,
            )

        blob_client.set_blob_metadata(metadata=metadata, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        blob_props = blob_client.get_blob_properties()
        md = blob_props.metadata
        self.assertEqual(3, len(md))
        self.assertEqual(md['hello'], 'world')
        self.assertEqual(md['number'], '42')
        self.assertEqual(md['up'], 'upval')
        self.assertFalse('Up' in md)
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_snapshot_blob(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        # test chunking functionality by reducing the size of each chunk,
        # otherwise the tests would take too long to execute
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        blob_client, _ = self._create_block_blob(bsc, data=b'AAABBBCCC', encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Act without cpk should not work
        with self.assertRaises(HttpResponseError):
            blob_client.create_snapshot()

        # Act with cpk should work
        blob_snapshot = blob_client.create_snapshot(encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        # Assert
        self.assertIsNotNone(blob_snapshot)
        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_list_blobs(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        self._setup(bsc)
        blob_client, _ = self._create_block_blob(bsc, blob_name="blockblob", data=b'AAABBBCCC', encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)
        self._create_append_blob(bsc, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        container_client = bsc.get_container_client(self.container_name)

        generator = container_client.list_blobs(include="metadata")
        for blob in generator:
            self.assertIsNotNone(blob)
            # Assert: every listed blob has encryption_scope
            self.assertEqual(blob.encryption_scope, TEST_ENCRYPTION_KEY_SCOPE)

        self._teardown(bsc)

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_create_container_with_default_cpk_n(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        container_client = bsc.create_container('cpkcontainer',
                                                default_encryption_scope=TEST_CONTAINER_ENCRYPTION_KEY_SCOPE)

        blob_client = container_client.get_blob_client("appendblob")

        # providing encryption scope when upload the blob
        resp = blob_client.upload_blob(b'aaaa', BlobType.AppendBlob, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)
        # Use the provided encryption scope on the blob
        self.assertEqual(resp['encryption_scope'], TEST_ENCRYPTION_KEY_SCOPE)

        container_client.delete_container()

    @pytest.mark.playback_test_only
    @GlobalStorageAccountPreparer()
    def test_create_container_with_default_cpk_n_deny_override(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        bsc = BlobServiceClient(
            self.account_url(storage_account, "blob"),
            credential=storage_account_key,
            connection_data_block_size=1024,
            max_single_put_size=1024,
            min_large_block_upload_threshold=1024,
            max_block_size=1024,
            max_page_size=1024)
        container_client = bsc.create_container(
            'cpkcontainerwithdenyoverride',
            default_encryption_scope=(TEST_CONTAINER_ENCRYPTION_KEY_SCOPE, True)
        )

        blob_client = container_client.get_blob_client("appendblob")

        # It's not allowed to set encryption scope on the blob when the container denies encryption scope override.
        with self.assertRaises(HttpResponseError):
            blob_client.upload_blob(b'aaaa', BlobType.AppendBlob, encryption_scope=TEST_ENCRYPTION_KEY_SCOPE)

        resp = blob_client.upload_blob(b'aaaa', BlobType.AppendBlob)

        self.assertEqual(resp['encryption_scope'], TEST_CONTAINER_ENCRYPTION_KEY_SCOPE)

        container_client.delete_container()
# ------------------------------------------------------------------------------
