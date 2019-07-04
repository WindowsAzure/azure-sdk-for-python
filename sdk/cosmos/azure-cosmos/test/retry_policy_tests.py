﻿#The MIT License (MIT)
#Copyright (c) 2014 Microsoft Corporation

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

import unittest
import uuid
import azure.cosmos.cosmos_client as cosmos_client
import pytest
import azure.cosmos.documents as documents
import azure.cosmos.errors as errors
import azure.cosmos.retry_options as retry_options
from azure.cosmos.http_constants import HttpHeaders, StatusCodes, SubStatusCodes
import azure.cosmos.retry_utility as retry_utility
import test_config

#IMPORTANT NOTES: 
  
#  	Most test cases in this file create collections in your Azure Cosmos account.
#  	Collections are billing entities.  By running these test cases, you may incur monetary costs on your account.

#  	To Run the test, replace the two member fields (masterKey and host) with values 
#   associated with your Azure Cosmos account.

@pytest.mark.usefixtures("teardown")
class Test_retry_policy_tests(unittest.TestCase):

    host = test_config._test_config.host
    masterKey = test_config._test_config.masterKey
    connectionPolicy = test_config._test_config.connectionPolicy
    counter = 0

    def __AssertHTTPFailureWithStatus(self, status_code, func, *args, **kwargs):
        """Assert HTTP failure with status.

        :Parameters:
            - `status_code`: int
            - `func`: function
        """
        try:
            func(*args, **kwargs)
            self.assertFalse(True, 'function should fail.')
        except errors.HTTPFailure as inst:
            self.assertEqual(inst.status_code, status_code)

    @classmethod
    def setUpClass(cls):
        if (cls.masterKey == '[YOUR_KEY_HERE]' or
                cls.host == '[YOUR_ENDPOINT_HERE]'):
            raise Exception(
                "You must specify your Azure Cosmos account values for "
                "'masterKey' and 'host' at the top of this class to run the "
                "tests.")

        cls.client = cosmos_client.CosmosClient(cls.host, {'masterKey': cls.masterKey}, "Session", cls.connectionPolicy)
        cls.created_collection = test_config._test_config.create_single_partition_collection_if_not_exist(cls.client)
        cls.retry_after_in_milliseconds = 1000

    def test_resource_throttle_retry_policy_default_retry_after(self):
        connection_policy = Test_retry_policy_tests.connectionPolicy
        connection_policy.RetryOptions = retry_options.RetryOptions(5)

        self.OriginalExecuteFunction = retry_utility._ExecuteFunction
        retry_utility._ExecuteFunction = self._MockExecuteFunction

        document_definition = { 'id': 'doc',
                                'name': 'sample document',
                                'key': 'value'} 

        try:
            self.created_collection.create_item(body=document_definition)
        except errors.HTTPFailure as e:
            self.assertEqual(e.status_code, StatusCodes.TOO_MANY_REQUESTS)
            self.assertEqual(connection_policy.RetryOptions.MaxRetryAttemptCount, self.created_collection.client_connection.last_response_headers[HttpHeaders.ThrottleRetryCount])
            self.assertGreaterEqual( self.created_collection.client_connection.last_response_headers[HttpHeaders.ThrottleRetryWaitTimeInMs],
                                     connection_policy.RetryOptions.MaxRetryAttemptCount * self.retry_after_in_milliseconds)

        retry_utility._ExecuteFunction = self.OriginalExecuteFunction

    def test_resource_throttle_retry_policy_fixed_retry_after(self):
        connection_policy = Test_retry_policy_tests.connectionPolicy
        connection_policy.RetryOptions = retry_options.RetryOptions(5, 2000)

        self.OriginalExecuteFunction = retry_utility._ExecuteFunction
        retry_utility._ExecuteFunction = self._MockExecuteFunction

        document_definition = { 'id': 'doc',
                                'name': 'sample document',
                                'key': 'value'} 

        try:
            self.created_collection.create_item(body=document_definition)
        except errors.HTTPFailure as e:
            self.assertEqual(e.status_code, StatusCodes.TOO_MANY_REQUESTS)
            self.assertEqual(connection_policy.RetryOptions.MaxRetryAttemptCount, self.created_collection.client_connection.last_response_headers[HttpHeaders.ThrottleRetryCount])
            self.assertGreaterEqual(self.created_collection.client_connection.last_response_headers[HttpHeaders.ThrottleRetryWaitTimeInMs],
                                    connection_policy.RetryOptions.MaxRetryAttemptCount * connection_policy.RetryOptions.FixedRetryIntervalInMilliseconds)

        retry_utility._ExecuteFunction = self.OriginalExecuteFunction

    def test_resource_throttle_retry_policy_max_wait_time(self):
        connection_policy = Test_retry_policy_tests.connectionPolicy
        connection_policy.RetryOptions = retry_options.RetryOptions(5, 2000, 3)

        self.OriginalExecuteFunction = retry_utility._ExecuteFunction
        retry_utility._ExecuteFunction = self._MockExecuteFunction

        document_definition = { 'id': 'doc',
                                'name': 'sample document',
                                'key': 'value'} 

        try:
            self.created_collection.create_item(body=document_definition)
        except errors.HTTPFailure as e:
            self.assertEqual(e.status_code, StatusCodes.TOO_MANY_REQUESTS)
            self.assertGreaterEqual(self.created_collection.client_connection.last_response_headers[HttpHeaders.ThrottleRetryWaitTimeInMs],
                                    connection_policy.RetryOptions.MaxWaitTimeInSeconds * 1000)

        retry_utility._ExecuteFunction = self.OriginalExecuteFunction

    def test_resource_throttle_retry_policy_query(self):
        connection_policy = Test_retry_policy_tests.connectionPolicy
        connection_policy.RetryOptions = retry_options.RetryOptions(5)

        document_definition = { 'id': 'doc',
                                'name': 'sample document',
                                'key': 'value'} 

        self.created_collection.create_item(body=document_definition)

        self.OriginalExecuteFunction = retry_utility._ExecuteFunction
        retry_utility._ExecuteFunction = self._MockExecuteFunction

        try:
            list(self.created_collection.query_items(
            {
                'query': 'SELECT * FROM root r WHERE r.id=@id',
                'parameters': [
                    { 'name':'@id', 'value':document_definition['id'] }
                ]
            }))
        except errors.HTTPFailure as e:
            self.assertEqual(e.status_code, StatusCodes.TOO_MANY_REQUESTS)
            self.assertEqual(connection_policy.RetryOptions.MaxRetryAttemptCount,
                             self.created_collection.client_connection.last_response_headers[HttpHeaders.ThrottleRetryCount])
            self.assertGreaterEqual(self.created_collection.client_connection.last_response_headers[HttpHeaders.ThrottleRetryWaitTimeInMs],
                                    connection_policy.RetryOptions.MaxRetryAttemptCount * self.retry_after_in_milliseconds)

        retry_utility._ExecuteFunction = self.OriginalExecuteFunction

    def test_default_retry_policy_for_query(self):
        document_definition_1 = { 'id': 'doc1',
                                  'name': 'sample document',
                                  'key': 'value'} 
        document_definition_2 = { 'id': 'doc2',
                                  'name': 'sample document',
                                  'key': 'value'} 

        self.created_collection.create_item(body=document_definition_1)
        self.created_collection.create_item(body=document_definition_2)

        self.OriginalExecuteFunction = retry_utility._ExecuteFunction
        retry_utility._ExecuteFunction = self._MockExecuteFunctionConnectionReset

        docs = self.created_collection.query_items(query="Select * from c", max_item_count=1, enable_cross_partition_query=True)
        
        result_docs = list(docs)
        self.assertEqual(result_docs[0]['id'], 'doc1')
        self.assertEqual(result_docs[1]['id'], 'doc2')
        self.assertEqual(self.counter, 12)

        self.counter = 0
        retry_utility._ExecuteFunction = self.OriginalExecuteFunction

        self.created_collection.delete_item(item=result_docs[0], partition_key=result_docs[0]['id'])
        self.created_collection.delete_item(item=result_docs[1], partition_key=result_docs[1]['id'])

    def test_default_retry_policy_for_read(self):
        connection_policy = Test_retry_policy_tests.connectionPolicy

        document_definition = { 'id': 'doc',
                                'name': 'sample document',
                                'key': 'value'} 

        created_document = self.created_collection.create_item(body=document_definition)

        self.OriginalExecuteFunction = retry_utility._ExecuteFunction
        retry_utility._ExecuteFunction = self._MockExecuteFunctionConnectionReset

        doc = self.created_collection.read_item(item=created_document['id'], partition_key=created_document['id'])
        self.assertEqual(doc['id'], 'doc')
        self.assertEqual(self.counter, 3)
        
        self.counter = 0
        retry_utility._ExecuteFunction = self.OriginalExecuteFunction
                
        self.created_collection.delete_item(item=created_document, partition_key=created_document['id'])
    
    def test_default_retry_policy_for_create(self):
        document_definition = { 'id': 'doc',
                                'name': 'sample document',
                                'key': 'value'} 

        self.OriginalExecuteFunction = retry_utility._ExecuteFunction
        retry_utility._ExecuteFunction = self._MockExecuteFunctionConnectionReset

        created_document = {}
        try :
            created_document = self.created_collection.create_item(body=document_definition)
        except errors.HTTPFailure as err:
            self.assertEqual(err.status_code, 10054)

        self.assertDictEqual(created_document, {})

        # 3 retries for readCollection. No retry for createDocument.
        self.assertEqual(self.counter, 4)

        retry_utility._ExecuteFunction = self.OriginalExecuteFunction

    def _MockExecuteFunction(self, function, *args, **kwargs):
        raise errors.HTTPFailure(StatusCodes.TOO_MANY_REQUESTS, "Request rate is too large", {HttpHeaders.RetryAfterInMilliseconds: self.retry_after_in_milliseconds})

    def _MockExecuteFunctionConnectionReset(self, function, *args, **kwargs):
        self.counter += 1
        if self.counter % 3 == 0:
            return self.OriginalExecuteFunction(function, *args, **kwargs)
        else:
            raise errors.HTTPFailure(10054, "Connection was reset", {})


if __name__ == '__main__':
    unittest.main()
