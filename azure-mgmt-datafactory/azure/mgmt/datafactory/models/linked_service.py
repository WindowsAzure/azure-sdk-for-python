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


class LinkedService(Model):
    """The Azure Data Factory nested object which contains the information and
    credential which can be used to connect with related store or compute
    resource.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AzureFunctionLinkedService,
    AzureDataExplorerLinkedService, GoogleAdWordsLinkedService,
    OracleServiceCloudLinkedService, DynamicsAXLinkedService,
    ResponsysLinkedService, AzureDatabricksLinkedService,
    AzureDataLakeAnalyticsLinkedService, HDInsightOnDemandLinkedService,
    SalesforceMarketingCloudLinkedService, NetezzaLinkedService,
    VerticaLinkedService, ZohoLinkedService, XeroLinkedService,
    SquareLinkedService, SparkLinkedService, ShopifyLinkedService,
    ServiceNowLinkedService, QuickBooksLinkedService, PrestoLinkedService,
    PhoenixLinkedService, PaypalLinkedService, MarketoLinkedService,
    MariaDBLinkedService, MagentoLinkedService, JiraLinkedService,
    ImpalaLinkedService, HubspotLinkedService, HiveLinkedService,
    HBaseLinkedService, GreenplumLinkedService, GoogleBigQueryLinkedService,
    EloquaLinkedService, DrillLinkedService, CouchbaseLinkedService,
    ConcurLinkedService, AzurePostgreSqlLinkedService, AmazonMWSLinkedService,
    SapHanaLinkedService, SapBWLinkedService, SftpServerLinkedService,
    FtpServerLinkedService, HttpLinkedService, AzureSearchLinkedService,
    CustomDataSourceLinkedService, AmazonRedshiftLinkedService,
    AmazonS3LinkedService, RestServiceLinkedService, SapOpenHubLinkedService,
    SapEccLinkedService, SapCloudForCustomerLinkedService,
    SalesforceLinkedService, Office365LinkedService, AzureBlobFSLinkedService,
    AzureDataLakeStoreLinkedService, CosmosDbMongoDbApiLinkedService,
    MongoDbV2LinkedService, MongoDbLinkedService, CassandraLinkedService,
    WebLinkedService, ODataLinkedService, HdfsLinkedService, OdbcLinkedService,
    AzureMLLinkedService, TeradataLinkedService, Db2LinkedService,
    SybaseLinkedService, PostgreSqlLinkedService, MySqlLinkedService,
    AzureMySqlLinkedService, OracleLinkedService, FileServerLinkedService,
    HDInsightLinkedService, DynamicsLinkedService, CosmosDbLinkedService,
    AzureKeyVaultLinkedService, AzureBatchLinkedService,
    AzureSqlDatabaseLinkedService, SqlServerLinkedService,
    AzureSqlDWLinkedService, AzureTableStorageLinkedService,
    AzureBlobStorageLinkedService, AzureStorageLinkedService

    All required parameters must be populated in order to send to Azure.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param connect_via: The integration runtime reference.
    :type connect_via:
     ~azure.mgmt.datafactory.models.IntegrationRuntimeReference
    :param description: Linked service description.
    :type description: str
    :param parameters: Parameters for linked service.
    :type parameters: dict[str,
     ~azure.mgmt.datafactory.models.ParameterSpecification]
    :param annotations: List of tags that can be used for describing the
     Dataset.
    :type annotations: list[object]
    :param type: Required. Constant filled by server.
    :type type: str
    """

    _validation = {
        'type': {'required': True},
    }

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'connect_via': {'key': 'connectVia', 'type': 'IntegrationRuntimeReference'},
        'description': {'key': 'description', 'type': 'str'},
        'parameters': {'key': 'parameters', 'type': '{ParameterSpecification}'},
        'annotations': {'key': 'annotations', 'type': '[object]'},
        'type': {'key': 'type', 'type': 'str'},
    }

    _subtype_map = {
        'type': {'AzureFunction': 'AzureFunctionLinkedService', 'AzureDataExplorer': 'AzureDataExplorerLinkedService', 'GoogleAdWords': 'GoogleAdWordsLinkedService', 'OracleServiceCloud': 'OracleServiceCloudLinkedService', 'DynamicsAX': 'DynamicsAXLinkedService', 'Responsys': 'ResponsysLinkedService', 'AzureDatabricks': 'AzureDatabricksLinkedService', 'AzureDataLakeAnalytics': 'AzureDataLakeAnalyticsLinkedService', 'HDInsightOnDemand': 'HDInsightOnDemandLinkedService', 'SalesforceMarketingCloud': 'SalesforceMarketingCloudLinkedService', 'Netezza': 'NetezzaLinkedService', 'Vertica': 'VerticaLinkedService', 'Zoho': 'ZohoLinkedService', 'Xero': 'XeroLinkedService', 'Square': 'SquareLinkedService', 'Spark': 'SparkLinkedService', 'Shopify': 'ShopifyLinkedService', 'ServiceNow': 'ServiceNowLinkedService', 'QuickBooks': 'QuickBooksLinkedService', 'Presto': 'PrestoLinkedService', 'Phoenix': 'PhoenixLinkedService', 'Paypal': 'PaypalLinkedService', 'Marketo': 'MarketoLinkedService', 'MariaDB': 'MariaDBLinkedService', 'Magento': 'MagentoLinkedService', 'Jira': 'JiraLinkedService', 'Impala': 'ImpalaLinkedService', 'Hubspot': 'HubspotLinkedService', 'Hive': 'HiveLinkedService', 'HBase': 'HBaseLinkedService', 'Greenplum': 'GreenplumLinkedService', 'GoogleBigQuery': 'GoogleBigQueryLinkedService', 'Eloqua': 'EloquaLinkedService', 'Drill': 'DrillLinkedService', 'Couchbase': 'CouchbaseLinkedService', 'Concur': 'ConcurLinkedService', 'AzurePostgreSql': 'AzurePostgreSqlLinkedService', 'AmazonMWS': 'AmazonMWSLinkedService', 'SapHana': 'SapHanaLinkedService', 'SapBW': 'SapBWLinkedService', 'Sftp': 'SftpServerLinkedService', 'FtpServer': 'FtpServerLinkedService', 'HttpServer': 'HttpLinkedService', 'AzureSearch': 'AzureSearchLinkedService', 'CustomDataSource': 'CustomDataSourceLinkedService', 'AmazonRedshift': 'AmazonRedshiftLinkedService', 'AmazonS3': 'AmazonS3LinkedService', 'RestService': 'RestServiceLinkedService', 'SapOpenHub': 'SapOpenHubLinkedService', 'SapEcc': 'SapEccLinkedService', 'SapCloudForCustomer': 'SapCloudForCustomerLinkedService', 'Salesforce': 'SalesforceLinkedService', 'Office365': 'Office365LinkedService', 'AzureBlobFS': 'AzureBlobFSLinkedService', 'AzureDataLakeStore': 'AzureDataLakeStoreLinkedService', 'CosmosDbMongoDbApi': 'CosmosDbMongoDbApiLinkedService', 'MongoDbV2': 'MongoDbV2LinkedService', 'MongoDb': 'MongoDbLinkedService', 'Cassandra': 'CassandraLinkedService', 'Web': 'WebLinkedService', 'OData': 'ODataLinkedService', 'Hdfs': 'HdfsLinkedService', 'Odbc': 'OdbcLinkedService', 'AzureML': 'AzureMLLinkedService', 'Teradata': 'TeradataLinkedService', 'Db2': 'Db2LinkedService', 'Sybase': 'SybaseLinkedService', 'PostgreSql': 'PostgreSqlLinkedService', 'MySql': 'MySqlLinkedService', 'AzureMySql': 'AzureMySqlLinkedService', 'Oracle': 'OracleLinkedService', 'FileServer': 'FileServerLinkedService', 'HDInsight': 'HDInsightLinkedService', 'Dynamics': 'DynamicsLinkedService', 'CosmosDb': 'CosmosDbLinkedService', 'AzureKeyVault': 'AzureKeyVaultLinkedService', 'AzureBatch': 'AzureBatchLinkedService', 'AzureSqlDatabase': 'AzureSqlDatabaseLinkedService', 'SqlServer': 'SqlServerLinkedService', 'AzureSqlDW': 'AzureSqlDWLinkedService', 'AzureTableStorage': 'AzureTableStorageLinkedService', 'AzureBlobStorage': 'AzureBlobStorageLinkedService', 'AzureStorage': 'AzureStorageLinkedService'}
    }

    def __init__(self, **kwargs):
        super(LinkedService, self).__init__(**kwargs)
        self.additional_properties = kwargs.get('additional_properties', None)
        self.connect_via = kwargs.get('connect_via', None)
        self.description = kwargs.get('description', None)
        self.parameters = kwargs.get('parameters', None)
        self.annotations = kwargs.get('annotations', None)
        self.type = None
