# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from datetime import datetime
import os
import sys

import pytest

from devtools_testutils import AzureTestCase

from azure.core import MatchConditions
from azure.core.exceptions import ResourceNotFoundError
from azure.data.tables import (
    EdmType,
    TableEntity,
    EntityProperty,
    UpdateMode,
    TableTransactionError,
    TableEntity,
    UpdateMode,
    TransactionOperation,
    RequestTooLargeError
)

from _shared.testcase import TableTestCase, SLEEP_DELAY
from preparers import cosmos_decorator

#------------------------------------------------------------------------------
TEST_TABLE_PREFIX = 'table'
#------------------------------------------------------------------------------

class StorageTableClientTest(AzureTestCase, TableTestCase):
    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_insert(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            # Act
            entity = TableEntity()
            entity['PartitionKey'] = '001'
            entity['RowKey'] = 'batch_insert_replace'
            entity['test'] = True
            entity['test2'] = 'value'
            entity['test3'] = 3
            entity['test4'] = EntityProperty(1234567890, EdmType.INT32)
            entity['test5'] = datetime.utcnow()

            batch = [('upsert', entity)]
            transaction_result = self.table.submit_transaction(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert 'etag' in transaction_result[0]

            entity = self.table.get_entity('001', 'batch_insert_replace')
            assert entity is not None
            assert 'value' ==  entity['test2']
            assert 1234567890 ==  entity['test4']
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_update(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            # Act
            entity = TableEntity()
            entity['PartitionKey'] = u'001'
            entity['RowKey'] = u'batch_update'
            entity['test'] = EntityProperty(True, EdmType.BOOLEAN)
            entity['test2'] = u'value'
            entity['test3'] = 3
            entity['test4'] = EntityProperty(1234567890, EdmType.INT32)
            entity['test5'] = datetime.utcnow()
            self.table.create_entity(entity)

            entity = self.table.get_entity(u'001', u'batch_update')
            assert 3 ==  entity['test3']
            entity['test2'] = u'value1'

            batch = [('update', entity)]
            transaction_result = self.table.submit_transaction(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert 'etag' in transaction_result[0]

            result = self.table.get_entity('001', 'batch_update')
            assert 'value1' ==  result['test2']
            assert entity['PartitionKey'] ==  u'001'
            assert entity['RowKey'] ==  u'batch_update'
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_merge(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            # Act
            entity = TableEntity()
            entity['PartitionKey'] = u'001'
            entity['RowKey'] = u'batch_merge'
            entity['test'] = EntityProperty(True, EdmType.BOOLEAN)
            entity['test2'] = u'value'
            entity['test3'] = 3
            entity['test4'] = EntityProperty(1234567890, EdmType.INT32)
            entity['test5'] = datetime.utcnow()
            self.table.create_entity(entity)

            resp_entity = self.table.get_entity(partition_key=u'001', row_key=u'batch_merge')
            assert 3 ==  entity['test3']
            entity = TableEntity()
            entity['PartitionKey'] = u'001'
            entity['RowKey'] = u'batch_merge'
            entity['test2'] = u'value1'

            batch = [('update', entity, {'mode': UpdateMode.MERGE})]
            transaction_result = self.table.submit_transaction(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert 'etag' in transaction_result[0]

            resp_entity = self.table.get_entity(partition_key=u'001', row_key=u'batch_merge')
            assert entity['test2'] ==  resp_entity['test2']
            assert 1234567890 ==  resp_entity['test4']
            assert entity['PartitionKey'] ==  resp_entity['PartitionKey']
            assert entity['RowKey'] ==  resp_entity['RowKey']
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_update_if_match(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            entity = self._create_random_entity_dict()
            resp = self.table.create_entity(entity=entity)
            etag = resp['etag']

            # Act
            sent_entity = self._create_updated_entity_dict(entity['PartitionKey'], entity['RowKey'])
            batch = [(
                'update',
                sent_entity,
                {'mode': UpdateMode.REPLACE, 'etag': etag, 'match_condition':MatchConditions.IfNotModified, 'mode':UpdateMode.REPLACE}
            )]
            transaction_result = self.table.submit_transaction(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert 'etag' in transaction_result[0]

            entity = self.table.get_entity(partition_key=entity['PartitionKey'], row_key=entity['RowKey'])
            self._assert_updated_entity(entity)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_update_if_doesnt_match(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            entity = self._create_random_entity_dict()
            self.table.create_entity(entity)

            # Act
            sent_entity1 = self._create_updated_entity_dict(entity['PartitionKey'], entity['RowKey'])

            batch = [(
                'update',
                sent_entity1,
                {'etag': u'W/"datetime\'2012-06-15T22%3A51%3A44.9662825Z\'"', 'match_condition':MatchConditions.IfNotModified}
            )]
            with pytest.raises(TableTransactionError):
                self.table.submit_transaction(batch)

            # Assert
            received_entity = self.table.get_entity(entity['PartitionKey'], entity['RowKey'])
            self._assert_default_entity(received_entity)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_insert_replace(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            # Act
            entity = TableEntity()
            entity['PartitionKey'] = '001'
            entity['RowKey'] = 'batch_insert_replace'
            entity['test'] = True
            entity['test2'] = 'value'
            entity['test3'] = 3
            entity['test4'] = EntityProperty(1234567890, EdmType.INT32)
            entity['test5'] = datetime.utcnow()

            batch = [('upsert', entity, {'mode': UpdateMode.REPLACE})]
            transaction_result = self.table.submit_transaction(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert 'etag' in transaction_result[0]

            entity = self.table.get_entity('001', 'batch_insert_replace')
            assert entity is not None
            assert 'value' ==  entity['test2']
            assert 1234567890 ==  entity['test4']
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_insert_merge(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            # Act
            entity = TableEntity()
            entity['PartitionKey'] = '001'
            entity['RowKey'] = 'batch_insert_merge'
            entity['test'] = True
            entity['test2'] = 'value'
            entity['test3'] = 3
            entity['test4'] = EntityProperty(1234567890, EdmType.INT32)
            entity['test5'] = datetime.utcnow()

            batch = [('upsert', entity, {'mode': UpdateMode.MERGE})]
            transaction_result = self.table.submit_transaction(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert 'etag' in transaction_result[0]

            entity = self.table.get_entity('001', 'batch_insert_merge')
            assert entity is not None
            assert 'value' ==  entity['test2']
            assert 1234567890 ==  entity['test4']
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_delete(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            # Act
            entity = TableEntity()
            entity['PartitionKey'] = u'001'
            entity['RowKey'] = u'batch_delete'
            entity['test'] = EntityProperty(True, EdmType.BOOLEAN)
            entity['test2'] = u'value'
            entity['test3'] = 3
            entity['test4'] = EntityProperty(1234567890, EdmType.INT32)
            entity['test5'] = datetime.utcnow()
            self.table.create_entity(entity)

            entity = self.table.get_entity(partition_key=u'001', row_key=u'batch_delete')
            assert 3 ==  entity['test3']

            batch = [('delete', entity)]
            transaction_result = self.table.submit_transaction(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert 'etag' not in transaction_result[0]

            with pytest.raises(ResourceNotFoundError):
                entity = self.table.get_entity(partition_key=entity['PartitionKey'], row_key=entity['RowKey'])
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_inserts(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            # Act
            entity = TableEntity()
            entity['PartitionKey'] = 'batch_inserts'
            entity['test'] = EntityProperty(True, EdmType.BOOLEAN)
            entity['test2'] = 'value'
            entity['test3'] = 3
            entity['test4'] = EntityProperty(1234567890, EdmType.INT32)

            transaction_count = 0
            batch = []
            for i in range(100):
                entity['RowKey'] = str(i)
                batch.append(('create', entity.copy()))
                transaction_count += 1
            transaction_result = self.table.submit_transaction(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, transaction_count)
            assert 'etag' in transaction_result[0]

            entities = list(self.table.query_entities("PartitionKey eq 'batch_inserts'"))

            # Assert
            assert entities is not None
            assert transaction_count ==  len(entities)
            e = self.table.get_entity('batch_inserts', '1')
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_all_operations_together(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            # Act
            entity = TableEntity()
            entity['PartitionKey'] = '003'
            entity['RowKey'] = 'batch_all_operations_together-1'
            entity['test'] = EntityProperty(True, EdmType.BOOLEAN)
            entity['test2'] = 'value'
            entity['test3'] = 3
            entity['test4'] = EntityProperty(1234567890, EdmType.INT32)
            entity['test5'] = datetime.utcnow()

            self.table.create_entity(entity)
            entity['RowKey'] = 'batch_all_operations_together-2'
            self.table.create_entity(entity)
            entity['RowKey'] = 'batch_all_operations_together-3'
            self.table.create_entity(entity)
            entity['RowKey'] = 'batch_all_operations_together-4'
            self.table.create_entity(entity)
            transaction_count = 0

            batch = []
            entity['RowKey'] = 'batch_all_operations_together'
            batch.append((TransactionOperation.CREATE, entity.copy()))
            transaction_count += 1

            entity['RowKey'] = 'batch_all_operations_together-1'
            batch.append((TransactionOperation.DELETE, entity.copy()))
            transaction_count += 1

            entity['RowKey'] = 'batch_all_operations_together-2'
            entity['test3'] = 10
            batch.append((TransactionOperation.UPDATE, entity.copy()))
            transaction_count += 1

            entity['RowKey'] = 'batch_all_operations_together-3'
            entity['test3'] = 100
            batch.append((TransactionOperation.UPDATE, entity.copy(), {'mode': UpdateMode.REPLACE}))
            transaction_count += 1

            entity['RowKey'] = 'batch_all_operations_together-4'
            entity['test3'] = 10
            batch.append((TransactionOperation.UPSERT, entity.copy()))
            transaction_count += 1

            entity['RowKey'] = 'batch_all_operations_together-5'
            batch.append((TransactionOperation.UPSERT, entity.copy(), {'mode': UpdateMode.REPLACE}))
            transaction_count += 1

            transaction_result = self.table.submit_transaction(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, transaction_count)
            assert 'etag' in transaction_result[0]
            assert 'etag' not in transaction_result[1]
            assert 'etag' in transaction_result[2]
            assert 'etag' in transaction_result[3]
            assert 'etag' in transaction_result[4]
            assert 'etag' in transaction_result[5]

            # Assert
            entities = list(self.table.query_entities("PartitionKey eq '003'"))
            assert 5 ==  len(entities)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_batch_different_partition_operations_fail(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')
            self.table.create_entity(entity)

            # Act
            batch = []

            entity = self._create_updated_entity_dict(
                '001', 'batch_negative_1')
            batch.append(('update', entity.copy()))

            entity = self._create_random_entity_dict(
                '002', 'batch_negative_1')
            batch.append(('update', entity.copy()))

            with pytest.raises(ValueError):
                self.table.submit_transaction(batch)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_new_non_existent_table(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')

            tc = self.ts.get_table_client("doesntexist")

            batch = [('create', entity)]

            with pytest.raises(TableTransactionError):
                resp = tc.submit_transaction(batch)
            # Assert
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_new_delete_nonexistent_entity(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')

            batch = [('delete', entity)]
            with pytest.raises(TableTransactionError):
                resp = self.table.submit_transaction(batch)

        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @cosmos_decorator
    def test_delete_batch_with_bad_kwarg(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')
            self.table.create_entity(entity)

            received = self.table.get_entity(entity["PartitionKey"], entity["RowKey"])
            good_etag = received.metadata["etag"]
            received.metadata["etag"] = u'W/"datetime\'2012-06-15T22%3A51%3A44.9662825Z\'"'

            batch = [('delete', received, {"match_condition": MatchConditions.IfNotModified})]

            with pytest.raises(TableTransactionError):
                self.table.submit_transaction(batch)

            received.metadata["etag"] = good_etag
            batch = [('delete', received, {"match_condition": MatchConditions.IfNotModified})]
            resp = self.table.submit_transaction(batch)

            assert resp is not None
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @pytest.mark.live_test_only  # Request bodies are very large
    @cosmos_decorator
    def test_batch_request_too_large(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key, url="cosmos")
        try:
            batch = []
            entity = {
                'PartitionKey': 'pk001',
                'Foo': os.urandom(1024*64),
                'Bar': os.urandom(1024*64),
                'Baz': os.urandom(1024*64)
            }
            for i in range(50):
                entity['RowKey'] = str(i)
                batch.append(('create', entity.copy()))

            with pytest.raises(RequestTooLargeError):
                self.table.submit_transaction(batch)

        finally:
            self._tear_down()
