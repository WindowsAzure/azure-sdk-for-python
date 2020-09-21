# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import unittest
import pytest

import uuid
from datetime import datetime
from dateutil.tz import tzutc
import sys

from azure.core import MatchConditions
from azure.core.exceptions import (
    ResourceExistsError,
    ResourceNotFoundError,
    HttpResponseError
)
from azure.data.tables import EdmType, TableEntity, EntityProperty, UpdateMode

from _shared.testcase import GlobalStorageAccountPreparer, TableTestCase, LogCaptured

from azure.data.tables._models import PartialBatchErrorException
from azure.data.tables import (
    TableServiceClient,
    TableEntity,
    UpdateMode,
)

#------------------------------------------------------------------------------
TEST_TABLE_PREFIX = 'table'
#------------------------------------------------------------------------------

class StorageTableBatchTest(TableTestCase):

    def _set_up(self, storage_account, storage_account_key):
        self.ts = TableServiceClient(self.account_url(storage_account, "table"), storage_account_key)
        self.table_name = self.get_resource_name('uttable')
        self.table = self.ts.get_table_client(self.table_name)
        if self.is_live:
            try:
                self.ts.create_table(self.table_name)
            except ResourceExistsError:
                pass

        self.test_tables = []

    def _tear_down(self):
        if self.is_live:
            try:
                self.ts.delete_table(self.table_name)
            except:
                pass

            for table_name in self.test_tables:
                try:
                    self.ts.delete_table(table_name)
                except:
                    pass

    #--Helpers-----------------------------------------------------------------

    def _get_table_reference(self, prefix=TEST_TABLE_PREFIX):
        table_name = self.get_resource_name(prefix)
        self.test_tables.append(table_name)
        return self.ts.get_table_client(table_name)

    def _create_pk_rk(self, pk, rk):
        try:
            pk = pk if pk is not None else self.get_resource_name('pk').decode('utf-8')
            rk = rk if rk is not None else self.get_resource_name('rk').decode('utf-8')
        except AttributeError:
            pk = pk if pk is not None else self.get_resource_name('pk')
            rk = rk if rk is not None else self.get_resource_name('rk')
        return pk, rk

    def _create_random_entity_dict(self, pk=None, rk=None):
        """
        Creates a dictionary-based entity with fixed values, using all
        of the supported data types.
        """
        # partition = pk if pk is not None else self.get_resource_name('pk').decode('utf-8')
        # row = rk if rk is not None else self.get_resource_name('rk').decode('utf-8')
        partition, row = self._create_pk_rk(pk, rk)
        properties = {
            'PartitionKey': partition,
            'RowKey': row,
            'age': 39,
            'sex': u'male',
            'married': True,
            'deceased': False,
            'optional': None,
            'ratio': 3.1,
            'evenratio': 3.0,
            'large': 933311100,
            'Birthday': datetime(1973, 10, 4, tzinfo=tzutc()),
            'birthday': datetime(1970, 10, 4, tzinfo=tzutc()),
            'binary': b'binary',
            'other': EntityProperty(value=20, type=EdmType.INT32),
            'clsid': uuid.UUID('c9da6455-213d-42c9-9a79-3e9149a57833')
        }
        return TableEntity(**properties)

    def _create_updated_entity_dict(self, partition, row):
        '''
        Creates a dictionary-based entity with fixed values, with a
        different set of values than the default entity. It
        adds fields, changes field values, changes field types,
        and removes fields when compared to the default entity.
        '''
        return {
            'PartitionKey': partition,
            'RowKey': row,
            'age': 'abc',
            'sex': 'female',
            'sign': 'aquarius',
            'birthday': datetime(1991, 10, 4, tzinfo=tzutc())
        }

    def _assert_default_entity(self, entity):
        '''
        Asserts that the entity passed in matches the default entity.
        '''
        self.assertEqual(entity['age'].value, 39)
        self.assertEqual(entity['sex'].value, 'male')
        self.assertEqual(entity['married'], True)
        self.assertEqual(entity['deceased'], False)
        self.assertFalse("optional" in entity)
        self.assertEqual(entity['ratio'], 3.1)
        self.assertEqual(entity['evenratio'], 3.0)
        self.assertEqual(entity['large'].value, 933311100)
        self.assertEqual(entity['Birthday'], datetime(1973, 10, 4, tzinfo=tzutc()))
        self.assertEqual(entity['birthday'], datetime(1970, 10, 4, tzinfo=tzutc()))
        self.assertEqual(entity['binary'].value, b'binary')
        self.assertIsInstance(entity['other'], EntityProperty)
        self.assertEqual(entity['other'].type, EdmType.INT32)
        self.assertEqual(entity['other'].value, 20)
        self.assertEqual(entity['clsid'], uuid.UUID('c9da6455-213d-42c9-9a79-3e9149a57833'))
        self.assertTrue('_metadata' in entity)

    def _assert_updated_entity(self, entity):
        '''
        Asserts that the entity passed in matches the updated entity.
        '''
        self.assertEqual(entity.age.value, 'abc')
        self.assertEqual(entity.sex.value, 'female')
        self.assertFalse(hasattr(entity, "married"))
        self.assertFalse(hasattr(entity, "deceased"))
        self.assertEqual(entity.sign.value, 'aquarius')
        self.assertFalse(hasattr(entity, "optional"))
        self.assertFalse(hasattr(entity, "ratio"))
        self.assertFalse(hasattr(entity, "evenratio"))
        self.assertFalse(hasattr(entity, "large"))
        self.assertFalse(hasattr(entity, "Birthday"))
        self.assertEqual(entity.birthday, datetime(1991, 10, 4, tzinfo=tzutc()))
        self.assertFalse(hasattr(entity, "other"))
        self.assertFalse(hasattr(entity, "clsid"))
        self.assertIsNotNone(entity['_metadata']['etag'])

    #--Test cases for batch ---------------------------------------------
    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_insert(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = '001'
            entity.RowKey = 'batch_insert'
            entity.test = EntityProperty(True)
            entity.test2 = 'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()

            batch = self.table.create_batch()
            batch.create_entity(entity)
            resp = self.table.commit_batch(batch)

            # Assert
            self.assertIsNotNone(resp)
            e = self.table.get_entity(row_key=entity.RowKey, partition_key=entity.PartitionKey)
            self.assertEqual(e.test, entity.test.value)
            self.assertEqual(e.test2.value, entity.test2)
            self.assertEqual(e.test3.value, entity.test3)
            self.assertEqual(e.test4.value, entity.test4.value)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_single_update(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = '001'
            entity.RowKey = 'batch_insert'
            entity.test = EntityProperty(True)
            entity.test2 = 'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()

            resp = self.table.create_entity(entity)
            self.assertIsNotNone(resp)

            entity.test3 = 5
            entity.test5 = datetime.utcnow()

            batch = self.table.create_batch()
            batch.update_entity(entity, mode=UpdateMode.MERGE)
            self.table.commit_batch(batch)

            # Assert
            self.assertIsNotNone(resp)
            result = self.table.get_entity(row_key=entity.RowKey, partition_key=entity.PartitionKey)
            self.assertEqual(result.PartitionKey, u'001')
            self.assertEqual(result.RowKey, u'batch_insert')
            self.assertEqual(result.test3.value, 5)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_update(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = u'001'
            entity.RowKey = u'batch_update'
            entity.test = EntityProperty(True)
            entity.test2 = u'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()
            self.table.create_entity(entity)

            entity = self.table.get_entity(u'001', u'batch_update')
            self.assertEqual(3, entity.test3.value)
            entity.test2 = u'value1'

            batch = self.table.create_batch()
            batch.update_entity(entity)
            resp = self.table.commit_batch(batch)

            # Assert
            self.assertIsNotNone(resp)
            result = self.table.get_entity('001', 'batch_update')
            self.assertEqual('value1', result.test2.value)
            self.assertEqual(entity.PartitionKey, u'001')
            self.assertEqual(entity.RowKey, u'batch_update')
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_merge(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = u'001'
            entity.RowKey = u'batch_merge'
            entity.test = EntityProperty(True)
            entity.test2 = u'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()
            self.table.create_entity(entity)

            resp_entity = self.table.get_entity(partition_key=u'001', row_key=u'batch_merge')
            self.assertEqual(3, entity.test3)
            entity = TableEntity()
            entity.PartitionKey = u'001'
            entity.RowKey = u'batch_merge'
            entity.test2 = u'value1'

            batch = self.table.create_batch()
            batch.update_entity(entity, mode=UpdateMode.MERGE)
            resp = self.table.commit_batch(batch)

            # Assert
            self.assertIsNotNone(resp)
            resp_entity = self.table.get_entity(partition_key=u'001', row_key=u'batch_merge')
            self.assertEqual(entity.test2, resp_entity.test2.value)
            self.assertEqual(1234567890, resp_entity.test4.value)
            self.assertEqual(entity.PartitionKey, resp_entity.PartitionKey)
            self.assertEqual(entity.RowKey, resp_entity.RowKey)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_update_if_match(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            entity = self._create_random_entity_dict()
            resp = self.table.create_entity(entity=entity)
            etag = resp['etag']

            # Act
            sent_entity = self._create_updated_entity_dict(entity['PartitionKey'], entity['RowKey'])
            batch = self.table.create_batch()
            batch.update_entity(
                sent_entity,
                etag=etag,
                match_condition=MatchConditions.IfNotModified,
                mode=UpdateMode.REPLACE
            )
            resp = self.table.commit_batch(batch)

            # Assert
            self.assertIsNotNone(resp)
            entity = self.table.get_entity(partition_key=entity['PartitionKey'], row_key=entity['RowKey'])
            self._assert_updated_entity(entity)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_update_if_doesnt_match(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            entity = self._create_random_entity_dict()
            self.table.create_entity(entity)

            # Act
            sent_entity1 = self._create_updated_entity_dict(entity['PartitionKey'], entity['RowKey'])

            batch = self.table.create_batch()
            batch.update_entity(
                sent_entity1,
                etag=u'W/"datetime\'2012-06-15T22%3A51%3A44.9662825Z\'"',
                match_condition=MatchConditions.IfNotModified
            )

            # TODO: This should be a PartialBatchErrorException
            with self.assertRaises(HttpResponseError):
                self.table.commit_batch(batch)

            # Assert
            received_entity = self.table.get_entity(entity['PartitionKey'], entity['RowKey'])
            self._assert_default_entity(received_entity)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_insert_replace(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = '001'
            entity.RowKey = 'batch_insert_replace'
            entity.test = True
            entity.test2 = 'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()

            batch = self.table.create_batch()
            batch.upsert_entity(entity)
            resp = self.table.commit_batch(batch)

            # Assert
            self.assertIsNotNone(resp)
            entity = self.table.get_entity('001', 'batch_insert_replace')
            self.assertIsNotNone(entity)
            self.assertEqual('value', entity.test2.value)
            self.assertEqual(1234567890, entity.test4.value)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_insert_merge(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = '001'
            entity.RowKey = 'batch_insert_merge'
            entity.test = True
            entity.test2 = 'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()

            batch = self.table.create_batch()
            batch.upsert_entity(entity, mode=UpdateMode.MERGE)
            resp = self.table.commit_batch(batch)

            # Assert
            self.assertIsNotNone(resp)
            entity = self.table.get_entity('001', 'batch_insert_merge')
            self.assertIsNotNone(entity)
            self.assertEqual('value', entity.test2.value)
            self.assertEqual(1234567890, entity.test4.value)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_delete(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = u'001'
            entity.RowKey = u'batch_delete'
            entity.test = EntityProperty(True)
            entity.test2 = u'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()
            self.table.create_entity(entity)

            entity = self.table.get_entity(partition_key=u'001', row_key=u'batch_delete')
            self.assertEqual(3, entity.test3.value)

            batch = self.table.create_batch()
            batch.delete_entity(partition_key=entity.PartitionKey, row_key=entity.RowKey)
            self.table.commit_batch(batch)

            with self.assertRaises(ResourceNotFoundError):
                entity = self.table.get_entity(partition_key=entity.PartitionKey, row_key=entity.RowKey)
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_inserts(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = 'batch_inserts'
            entity.test = EntityProperty(True)
            entity.test2 = 'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)

            batch = self.table.create_batch()
            for i in range(100):
                entity.RowKey = str(i)
                batch.create_entity(entity)
            self.table.commit_batch(batch)

            entities = list(self.table.query_entities("PartitionKey eq 'batch_inserts'"))

            # Assert
            self.assertIsNotNone(entities)
            self.assertEqual(100, len(entities))
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_all_operations_together(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = '003'
            entity.RowKey = 'batch_all_operations_together-1'
            entity.test = EntityProperty(True)
            entity.test2 = 'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()
            self.table.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-2'
            self.table.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-3'
            self.table.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-4'
            self.table.create_entity(entity)

            batch = self.table.create_batch()
            entity.RowKey = 'batch_all_operations_together'
            batch.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-1'
            batch.delete_entity(entity.PartitionKey, entity.RowKey)
            entity.RowKey = 'batch_all_operations_together-2'
            entity.test3 = 10
            batch.update_entity(entity)
            entity.RowKey = 'batch_all_operations_together-3'
            entity.test3 = 100
            batch.update_entity(entity, mode=UpdateMode.MERGE)
            entity.RowKey = 'batch_all_operations_together-4'
            entity.test3 = 10
            batch.upsert_entity(entity)
            entity.RowKey = 'batch_all_operations_together-5'
            batch.upsert_entity(entity, mode=UpdateMode.MERGE)
            resp = self.table.commit_batch(batch)

            # Assert
            self.assertIsNotNone(resp)
            entities = list(self.table.query_entities("PartitionKey eq '003'"))
            self.assertEqual(5, len(entities))
        finally:
            self._tear_down()

    @pytest.mark.skipif(sys.version_info < (3, 0), reason="requires Python3")
    @GlobalStorageAccountPreparer()
    def test_batch_all_operations_together_context_manager(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = '003'
            entity.RowKey = 'batch_all_operations_together-1'
            entity.test = EntityProperty(True)
            entity.test2 = 'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()
            self.table.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-2'
            self.table.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-3'
            self.table.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-4'
            self.table.create_entity(entity)

            with self.table.create_batch() as batch:
                entity.RowKey = 'batch_all_operations_together'
                batch.create_entity(entity)
                entity.RowKey = 'batch_all_operations_together-1'
                batch.delete_entity(entity.PartitionKey, entity.RowKey)
                entity.RowKey = 'batch_all_operations_together-2'
                entity.test3 = 10
                batch.update_entity(entity)
                entity.RowKey = 'batch_all_operations_together-3'
                entity.test3 = 100
                batch.update_entity(entity, mode=UpdateMode.MERGE)
                entity.RowKey = 'batch_all_operations_together-4'
                entity.test3 = 10
                batch.upsert_entity(entity)
                entity.RowKey = 'batch_all_operations_together-5'
                batch.upsert_entity(entity, mode=UpdateMode.MERGE)

            # Assert
            entities = list(self.table.query_entities("PartitionKey eq '003'"))
            self.assertEqual(5, len(entities))
        finally:
            self._tear_down()

    @pytest.mark.skip("Not sure this is how the batching should operate, will consult w/ Anna")
    @GlobalStorageAccountPreparer()
    def test_batch_reuse(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            table2 = self._get_table_reference('table2')
            table2.create_table()

            # Act
            entity = TableEntity()
            entity.PartitionKey = '003'
            entity.RowKey = 'batch_all_operations_together-1'
            entity.test = EntityProperty(True)
            entity.test2 = 'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            entity.test5 = datetime.utcnow()

            batch = self.table.create_batch()
            batch.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-2'
            batch.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-3'
            batch.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-4'
            batch.create_entity(entity)

            self.table.commit_batch(batch)
            table2.commit_batch(batch)

            batch = TableBatchClient()
            entity.RowKey = 'batch_all_operations_together'
            batch.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-1'
            batch.delete_entity(entity.PartitionKey, entity.RowKey)
            entity.RowKey = 'batch_all_operations_together-2'
            entity.test3 = 10
            batch.update_entity(entity)
            entity.RowKey = 'batch_all_operations_together-3'
            entity.test3 = 100
            batch.update_entity(entity, mode=UpdateMode.MERGE)
            entity.RowKey = 'batch_all_operations_together-4'
            entity.test3 = 10
            batch.upsert_entity(entity)
            entity.RowKey = 'batch_all_operations_together-5'
            batch.upsert_entity(entity, mode=UpdateMode.MERGE)

            self.table.commit_batch(batch)
            resp = table2.commit_batch(batch)

            # Assert
            self.assertEqual(6, len(list(resp)))
            entities = list(self.table.query_entities("PartitionKey eq '003'"))
            self.assertEqual(5, len(entities))
        finally:
            self._tear_down()

    @pytest.mark.skip("This does not throw an error, but it should")
    @GlobalStorageAccountPreparer()
    def test_batch_same_row_operations_fail(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')
            self.table.create_entity(entity)

            # Act
            batch = self.table.create_batch()

            entity = self._create_updated_entity_dict(
                '001', 'batch_negative_1')
            batch.update_entity(entity)
            entity = self._create_random_entity_dict(
                '001', 'batch_negative_1')

            # Assert
            with self.assertRaises(HttpResponseError):
                batch.update_entity(entity, mode=UpdateMode.MERGE)
        finally:
            self._tear_down()

    @pytest.mark.skip("This does not throw an error, but it should")
    @GlobalStorageAccountPreparer()
    def test_batch_different_partition_operations_fail(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')
            self.table.create_entity(entity)

            # Act
            batch = self.table.create_batch()

            entity = self._create_updated_entity_dict(
                '001', 'batch_negative_1')
            batch.update_entity(entity)

            entity = self._create_random_entity_dict(
                '002', 'batch_negative_1')
            batch.create_entity(entity)

            # Assert
            with self.assertRaises(ValueError):
                batch.create_entity(entity)
        finally:
            self._tear_down()

    @pytest.mark.skip("This does not throw an error, but it should")
    @GlobalStorageAccountPreparer()
    def test_batch_too_many_ops(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')
            self.table.create_entity(entity)

            # Act
            with self.assertRaises(ValueError):
                batch = self.table.create_batch()
                for i in range(0, 101):
                    entity = TableEntity()
                    entity.PartitionKey = 'large'
                    entity.RowKey = 'item{0}'.format(i)
                    batch.create_entity(entity)

            # Assert
        finally:
            self._tear_down()

    @pytest.mark.skip("This does not throw an error, but it should")
    @GlobalStorageAccountPreparer()
    def test_batch_different_partition_keys(self, resource_group, location, storage_account, storage_account_key):
        # Arrange
        self._set_up(storage_account, storage_account_key)
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')
            entity2 = self._create_random_entity_dict('002', 'batch_negative_1')

            batch = self.table.create_batch()
            batch.create_entity(entity)
            batch.create_entity(entity2)
            self.table.commit_batch(batch)

            # Assert
        finally:
            self._tear_down()

#------------------------------------------------------------------------------
if __name__ == '__main__':
    unittest.main()
