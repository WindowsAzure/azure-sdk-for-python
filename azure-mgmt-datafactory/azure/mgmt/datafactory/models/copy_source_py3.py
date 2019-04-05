# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class CopySource(Model):
    """A copy activity source.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AmazonRedshiftSource, ResponsysSource,
    SalesforceMarketingCloudSource, VerticaSource, NetezzaSource, ZohoSource,
    XeroSource, SquareSource, SparkSource, ShopifySource, ServiceNowSource,
    QuickBooksSource, PrestoSource, PhoenixSource, PaypalSource, MarketoSource,
    MariaDBSource, MagentoSource, JiraSource, ImpalaSource, HubspotSource,
    HiveSource, HBaseSource, GreenplumSource, GoogleBigQuerySource,
    EloquaSource, DrillSource, CouchbaseSource, ConcurSource,
    AzurePostgreSqlSource, AmazonMWSSource, HttpSource,
    AzureDataLakeStoreSource, MongoDbSource, CassandraSource, WebSource,
    OracleSource, AzureMySqlSource, HdfsSource, FileSystemSource, SqlDWSource,
    SqlSource, SapEccSource, SapCloudForCustomerSource, SalesforceSource,
    RelationalSource, DynamicsSource, DocumentDbCollectionSource, BlobSource,
    AzureTableSource

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param source_retry_count: Source retry count. Type: integer (or
     Expression with resultType integer).
    :type source_retry_count: object
    :param source_retry_wait: Source retry wait. Type: string (or Expression
     with resultType string), pattern:
     ((\\d+)\\.)?(\\d\\d):(60|([0-5][0-9])):(60|([0-5][0-9])).
    :type source_retry_wait: object
    :param type: Required. Constant filled by server.
    :type type: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'source_retry_count': {'key': 'sourceRetryCount', 'type': 'object'},
        'source_retry_wait': {'key': 'sourceRetryWait', 'type': 'object'},
        'type': {'key': 'type', 'type': 'str'},
    }

    _subtype_map = {
        'type': {'AmazonRedshiftSource': 'AmazonRedshiftSource', 'ResponsysSource': 'ResponsysSource', 'SalesforceMarketingCloudSource': 'SalesforceMarketingCloudSource', 'VerticaSource': 'VerticaSource', 'NetezzaSource': 'NetezzaSource', 'ZohoSource': 'ZohoSource', 'XeroSource': 'XeroSource', 'SquareSource': 'SquareSource', 'SparkSource': 'SparkSource', 'ShopifySource': 'ShopifySource', 'ServiceNowSource': 'ServiceNowSource', 'QuickBooksSource': 'QuickBooksSource', 'PrestoSource': 'PrestoSource', 'PhoenixSource': 'PhoenixSource', 'PaypalSource': 'PaypalSource', 'MarketoSource': 'MarketoSource', 'MariaDBSource': 'MariaDBSource', 'MagentoSource': 'MagentoSource', 'JiraSource': 'JiraSource', 'ImpalaSource': 'ImpalaSource', 'HubspotSource': 'HubspotSource', 'HiveSource': 'HiveSource', 'HBaseSource': 'HBaseSource', 'GreenplumSource': 'GreenplumSource', 'GoogleBigQuerySource': 'GoogleBigQuerySource', 'EloquaSource': 'EloquaSource', 'DrillSource': 'DrillSource', 'CouchbaseSource': 'CouchbaseSource', 'ConcurSource': 'ConcurSource', 'AzurePostgreSqlSource': 'AzurePostgreSqlSource', 'AmazonMWSSource': 'AmazonMWSSource', 'HttpSource': 'HttpSource', 'AzureDataLakeStoreSource': 'AzureDataLakeStoreSource', 'MongoDbSource': 'MongoDbSource', 'CassandraSource': 'CassandraSource', 'WebSource': 'WebSource', 'OracleSource': 'OracleSource', 'AzureMySqlSource': 'AzureMySqlSource', 'HdfsSource': 'HdfsSource', 'FileSystemSource': 'FileSystemSource', 'SqlDWSource': 'SqlDWSource', 'SqlSource': 'SqlSource', 'SapEccSource': 'SapEccSource', 'SapCloudForCustomerSource': 'SapCloudForCustomerSource', 'SalesforceSource': 'SalesforceSource', 'RelationalSource': 'RelationalSource', 'DynamicsSource': 'DynamicsSource', 'DocumentDbCollectionSource': 'DocumentDbCollectionSource', 'BlobSource': 'BlobSource', 'AzureTableSource': 'AzureTableSource'}
    }

    def __init__(self, *, additional_properties=None, source_retry_count=None, source_retry_wait=None, **kwargs) -> None:
        super(CopySource, self).__init__(**kwargs)
        self.additional_properties = additional_properties
        self.source_retry_count = source_retry_count
        self.source_retry_wait = source_retry_wait
        self.type = None
