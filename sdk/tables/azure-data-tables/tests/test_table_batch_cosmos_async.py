# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

from datetime import datetime
from dateutil.tz import tzutc
import os
import sys
import uuid

import pytest

from devtools_testutils import AzureTestCase

from azure.core import MatchConditions
from azure.core.exceptions import (
    ResourceExistsError,
    ResourceNotFoundError,
    HttpResponseError,
    ClientAuthenticationError
)
from azure.data.tables import (
    TableEntity,
    UpdateMode,
    EntityProperty,
    EdmType,
    BatchErrorException,
    RequestEntityTooLargeError
)
from azure.data.tables.aio import TableServiceClient

from _shared.testcase import SLEEP_DELAY
from _shared.asynctestcase import AsyncTableTestCase
from preparers import CosmosPreparer

#------------------------------------------------------------------------------
TEST_TABLE_PREFIX = 'table'
#------------------------------------------------------------------------------

class StorageTableBatchTest(AzureTestCase, AsyncTableTestCase):

    async def _set_up(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        self.ts = TableServiceClient(self.account_url(tables_cosmos_account_name, "cosmos"), tables_primary_cosmos_account_key)
        self.table_name = self.get_resource_name('uttable')
        self.table = self.ts.get_table_client(self.table_name)
        if self.is_live:
            try:
                await self.ts.create_table(self.table_name)
            except ResourceExistsError:
                pass
        self.test_tables = [self.table_name]

    async def _tear_down(self):
        if self.is_live:
            try:
                await self.ts.delete_table(self.table_name)
            except:
                pass

            for table_name in self.test_tables:
                try:
                    await self.ts.delete_table(table_name)
                except:
                    pass
        await self.table.close()
        self.test_tables = []
        self.sleep(SLEEP_DELAY)

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
            'age': u'abc',
            'sex': u'female',
            'sign': u'aquarius',
            'birthday': datetime(1991, 10, 4, tzinfo=tzutc())
        }

    def _assert_default_entity(self, entity):
        '''
        Asserts that the entity passed in matches the default entity.
        '''
        assert entity['age'] ==  39
        assert entity['sex'] ==  'male'
        assert entity['married'] ==  True
        assert entity['deceased'] ==  False
        assert not "optional" in entity
        assert entity['ratio'] ==  3.1
        assert entity['evenratio'] ==  3.0
        assert entity['large'] ==  933311100
        assert entity['Birthday'] == datetime(1973, 10, 4, tzinfo=tzutc())
        assert entity['birthday'] == datetime(1970, 10, 4, tzinfo=tzutc())
        assert entity['binary'].value ==  b'binary'
        assert entity['other'] ==  20
        assert entity['clsid'] ==  uuid.UUID('c9da6455-213d-42c9-9a79-3e9149a57833')
        assert '_metadata' in entity

    def _assert_updated_entity(self, entity):
        '''
        Asserts that the entity passed in matches the updated entity.
        '''
        assert entity.age ==  'abc'
        assert entity.sex ==  'female'
        assert not hasattr(entity, "married")
        assert not hasattr(entity, "deceased")
        assert entity.sign ==  'aquarius'
        assert not hasattr(entity, "optional")
        assert not hasattr(entity, "ratio")
        assert not hasattr(entity, "evenratio")
        assert not hasattr(entity, "large")
        assert not hasattr(entity, "Birthday")
        assert entity.birthday, datetime(1991, 10, 4, tzinfo=tzutc())
        assert not hasattr(entity, "other")
        assert not hasattr(entity, "clsid")
        assert entity['_metadata']['etag'] is not None

    def _assert_valid_batch_transaction(self, transaction, length):
        assert length ==  len(transaction)

    #--Test cases for batch ---------------------------------------------
    @CosmosPreparer()
    async def test_batch_single_insert(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
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
            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            sent_entity = transaction_result[0][0]
            assert 'etag' in transaction_result[0][1]

            assert sent_entity is not None
            e = await self.table.get_entity(row_key=entity.RowKey, partition_key=entity.PartitionKey)
            assert e.test ==  entity.test.value
            assert e.test2 ==  entity.test2
            assert e.test3 ==  entity.test3
            assert e.test4 ==  entity.test4.value
            assert sent_entity ==  entity

        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_single_update(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
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

            resp = await self.table.create_entity(entity)
            assert resp is not None

            entity.test3 = 5
            entity.test5 = datetime.utcnow()

            batch = self.table.create_batch()
            batch.update_entity(entity, mode=UpdateMode.MERGE)
            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert transaction_result[0][0]['RowKey'] == u'batch_insert'
            assert 'etag' in transaction_result[0][1]

            result = await self.table.get_entity(row_key=entity.RowKey, partition_key=entity.PartitionKey)
            assert result.PartitionKey ==  u'001'
            assert result.RowKey ==  u'batch_insert'
            assert result.test3 ==  5
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_update(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
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
            await self.table.create_entity(entity)

            entity = await self.table.get_entity(u'001', u'batch_update')
            assert 3 ==  entity.test3
            entity.test2 = u'value1'

            batch = self.table.create_batch()
            batch.update_entity(entity)
            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert transaction_result[0][0]['RowKey'] == u'batch_update'
            assert 'etag' in transaction_result[0][1]

            result = await self.table.get_entity('001', 'batch_update')
            assert 'value1' ==  result.test2
            assert entity.PartitionKey ==  u'001'
            assert entity.RowKey ==  u'batch_update'
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_merge(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
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
            await self.table.create_entity(entity)

            resp_entity = await self.table.get_entity(partition_key=u'001', row_key=u'batch_merge')
            assert 3 ==  entity.test3
            entity = TableEntity()
            entity.PartitionKey = u'001'
            entity.RowKey = u'batch_merge'
            entity.test2 = u'value1'

            batch = self.table.create_batch()
            batch.update_entity(entity, mode=UpdateMode.MERGE)
            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert transaction_result[0][0]['RowKey'] == u'batch_merge'
            assert 'etag' in transaction_result[0][1]

            resp_entity = await self.table.get_entity(partition_key=u'001', row_key=u'batch_merge')
            assert entity.test2 ==  resp_entity.test2
            assert 1234567890 ==  resp_entity.test4
            assert entity.PartitionKey ==  resp_entity.PartitionKey
            assert entity.RowKey ==  resp_entity.RowKey
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_update_if_match(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
        try:
            entity = self._create_random_entity_dict()
            resp = await self.table.create_entity(entity=entity)
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
            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert transaction_result[0][0]['RowKey'] == entity['RowKey']
            assert 'etag' in transaction_result[0][1]

            entity = await self.table.get_entity(partition_key=entity['PartitionKey'], row_key=entity['RowKey'])
            self._assert_updated_entity(entity)
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_update_if_doesnt_match(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
        try:
            entity = self._create_random_entity_dict()
            resp = await self.table.create_entity(entity)
            assert resp is not None

            # Act
            sent_entity1 = self._create_updated_entity_dict(entity['PartitionKey'], entity['RowKey'])

            batch = self.table.create_batch()
            batch.update_entity(
                sent_entity1,
                etag=u'W/"datetime\'2012-06-15T22%3A51%3A44.9662825Z\'"',
                match_condition=MatchConditions.IfNotModified
            )

            with pytest.raises(HttpResponseError):
                await self.table.send_batch(batch)

            # Assert
            received_entity = await self.table.get_entity(entity['PartitionKey'], entity['RowKey'])
            self._assert_default_entity(received_entity)
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_insert_replace(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
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
            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert transaction_result[0][0]['RowKey'] == u'batch_insert_replace'
            assert 'etag' in transaction_result[0][1]

            entity = await self.table.get_entity('001', 'batch_insert_replace')
            assert entity is not None
            assert 'value' ==  entity.test2
            assert 1234567890 ==  entity.test4
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_insert_merge(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
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
            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert transaction_result[0][0]['RowKey'] == u'batch_insert_merge'
            assert 'etag' in transaction_result[0][1]

            entity = await self.table.get_entity('001', 'batch_insert_merge')
            assert entity is not None
            assert 'value' ==  entity.test2
            assert 1234567890 ==  entity.test4
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_delete(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
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
            await self.table.create_entity(entity)

            entity = await self.table.get_entity(partition_key=u'001', row_key=u'batch_delete')
            assert 3 ==  entity.test3

            batch = self.table.create_batch()
            batch.delete_entity(partition_key=entity.PartitionKey, row_key=entity.RowKey)
            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, 1)
            assert transaction_result[0][0]['RowKey'] == u'batch_delete'
            assert 'etag' not in transaction_result[0][1]

            with pytest.raises(ResourceNotFoundError):
                entity = await self.table.get_entity(partition_key=entity.PartitionKey, row_key=entity.RowKey)
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_inserts(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
        try:
            # Act
            entity = TableEntity()
            entity.PartitionKey = 'batch_inserts'
            entity.test = EntityProperty(True)
            entity.test2 = 'value'
            entity.test3 = 3
            entity.test4 = EntityProperty(1234567890)
            transaction_count = 0

            batch = self.table.create_batch()
            for i in range(10):
                entity.RowKey = str(i)
                batch.create_entity(entity)
                transaction_count += 1
            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, transaction_count)
            assert transaction_result[0][0]['RowKey'] == u'0'
            assert transaction_result[transaction_count - 1][0]['RowKey'] == str(transaction_count-1)
            assert 'etag' in transaction_result[0][1]

            entities = self.table.query_entities("PartitionKey eq 'batch_inserts'")

            length = 0
            async for e in entities:
                length += 1

            # Assert
            assert entities is not None
            assert 10 == length
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_all_operations_together(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
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
            await self.table.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-2'
            await self.table.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-3'
            await self.table.create_entity(entity)
            entity.RowKey = 'batch_all_operations_together-4'
            await self.table.create_entity(entity)

            transaction_count = 0

            batch = self.table.create_batch()
            entity.RowKey = 'batch_all_operations_together'
            batch.create_entity(entity)
            transaction_count += 1

            entity.RowKey = 'batch_all_operations_together-1'
            batch.delete_entity(entity.PartitionKey, entity.RowKey)
            transaction_count += 1

            entity.RowKey = 'batch_all_operations_together-2'
            entity.test3 = 10
            batch.update_entity(entity)
            transaction_count += 1

            entity.RowKey = 'batch_all_operations_together-3'
            entity.test3 = 100
            batch.update_entity(entity, mode=UpdateMode.MERGE)
            transaction_count += 1

            entity.RowKey = 'batch_all_operations_together-4'
            entity.test3 = 10
            batch.upsert_entity(entity)
            transaction_count += 1

            entity.RowKey = 'batch_all_operations_together-5'
            batch.upsert_entity(entity, mode=UpdateMode.MERGE)
            transaction_count += 1

            transaction_result = await self.table.send_batch(batch)

            # Assert
            self._assert_valid_batch_transaction(transaction_result, transaction_count)
            assert transaction_result[0][0]['RowKey'] == u'batch_all_operations_together'
            assert 'etag' in transaction_result[0][1]
            assert transaction_result[1][0]['RowKey'] == u'batch_all_operations_together-1'
            assert 'etag' not in transaction_result[1][1]
            assert transaction_result[2][0]['RowKey'] == u'batch_all_operations_together-2'
            assert 'etag' in transaction_result[2][1]
            assert transaction_result[3][0]['RowKey'] == u'batch_all_operations_together-3'
            assert 'etag' in transaction_result[3][1]
            assert transaction_result[4][0]['RowKey'] == u'batch_all_operations_together-4'
            assert 'etag' in transaction_result[4][1]
            assert transaction_result[5][0]['RowKey'] == u'batch_all_operations_together-5'
            assert 'etag' in transaction_result[5][1]

            entities = self.table.query_entities("PartitionKey eq '003'")
            length = 0
            async for e in entities:
                length += 1
            assert 5 ==  length
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_batch_different_partition_operations_fail(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')
            await self.table.create_entity(entity)

            # Act
            batch = self.table.create_batch()

            entity = self._create_updated_entity_dict(
                '001', 'batch_negative_1')
            batch.update_entity(entity)

            entity = self._create_random_entity_dict(
                '002', 'batch_negative_1')

            # Assert
            with pytest.raises(ValueError):
                batch.create_entity(entity)
        finally:
            await self._tear_down()

    @CosmosPreparer()
    async def test_new_non_existent_table(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')

            tc = self.ts.get_table_client("doesntexist")

            batch = tc.create_batch()
            batch.create_entity(entity)

            with pytest.raises(ResourceNotFoundError):
                resp = await tc.send_batch(batch)
            # Assert
        finally:
            await self._tear_down()

    @pytest.mark.live_test_only
    @CosmosPreparer()
    async def test_new_invalid_key(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        invalid_key = tables_primary_cosmos_account_key[0:-6] + "==" # cut off a bit from the end to invalidate
        key_list = list(tables_primary_cosmos_account_key)

        key_list[-6:] = list("0000==")
        invalid_key = ''.join(key_list)

        self.ts = TableServiceClient(self.account_url(tables_cosmos_account_name, "table"), invalid_key)
        self.table_name = self.get_resource_name('uttable')
        self.table = self.ts.get_table_client(self.table_name)

        entity = self._create_random_entity_dict('001', 'batch_negative_1')

        batch = self.table.create_batch()
        batch.create_entity(entity)

        with pytest.raises(ClientAuthenticationError):
            resp = await self.table.send_batch(batch)

    @CosmosPreparer()
    async def test_new_delete_nonexistent_entity(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
        try:
            entity = self._create_random_entity_dict('001', 'batch_negative_1')

            batch = self.table.create_batch()
            batch.delete_entity(entity['PartitionKey'], entity['RowKey'])

            with pytest.raises(ResourceNotFoundError):
                resp = await self.table.send_batch(batch)

        finally:
            await self._tear_down()

    @pytest.mark.live_test_only  # Request bodies are very large
    @CosmosPreparer()
    async def test_batch_request_too_large(self, tables_cosmos_account_name, tables_primary_cosmos_account_key):
        # Arrange
        await self._set_up(tables_cosmos_account_name, tables_primary_cosmos_account_key)
        try:

            batch = self.table.create_batch()
            entity = {
                'PartitionKey': 'pk001',
                'Foo': os.urandom(1024*64),
                'Bar': os.urandom(1024*64),
                'Baz': os.urandom(1024*64)
            }
            for i in range(20):
                entity['RowKey'] = str(i)
                batch.create_entity(entity)

            with pytest.raises(RequestEntityTooLargeError):
                await self.table.send_batch(batch)

        finally:
            await self._tear_down()

