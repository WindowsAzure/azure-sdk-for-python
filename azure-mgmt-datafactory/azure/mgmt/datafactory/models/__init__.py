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

from .resource import Resource
from .sub_resource import SubResource
from .expression import Expression
from .secure_string import SecureString
from .linked_service_reference import LinkedServiceReference
from .azure_key_vault_secret_reference import AzureKeyVaultSecretReference
from .secret_base import SecretBase
from .factory_identity import FactoryIdentity
from .factory import Factory
from .integration_runtime import IntegrationRuntime
from .integration_runtime_resource import IntegrationRuntimeResource
from .integration_runtime_reference import IntegrationRuntimeReference
from .integration_runtime_status import IntegrationRuntimeStatus
from .integration_runtime_status_response import IntegrationRuntimeStatusResponse
from .integration_runtime_status_list_response import IntegrationRuntimeStatusListResponse
from .update_integration_runtime_request import UpdateIntegrationRuntimeRequest
from .update_integration_runtime_node_request import UpdateIntegrationRuntimeNodeRequest
from .linked_service import LinkedService
from .linked_service_resource import LinkedServiceResource
from .parameter_specification import ParameterSpecification
from .dataset import Dataset
from .dataset_resource import DatasetResource
from .activity_dependency import ActivityDependency
from .activity import Activity
from .pipeline_resource import PipelineResource
from .trigger import Trigger
from .trigger_resource import TriggerResource
from .create_run_response import CreateRunResponse
from .error_response import ErrorResponse, ErrorResponseException
from .pipeline_reference import PipelineReference
from .trigger_pipeline_reference import TriggerPipelineReference
from .factory_update_parameters import FactoryUpdateParameters
from .dataset_reference import DatasetReference
from .pipeline_run_query_filter import PipelineRunQueryFilter
from .pipeline_run_query_order_by import PipelineRunQueryOrderBy
from .pipeline_run_filter_parameters import PipelineRunFilterParameters
from .pipeline_run_invoked_by import PipelineRunInvokedBy
from .pipeline_run import PipelineRun
from .pipeline_run_query_response import PipelineRunQueryResponse
from .activity_run import ActivityRun
from .trigger_run import TriggerRun
from .operation_display import OperationDisplay
from .operation_log_specification import OperationLogSpecification
from .operation_metric_availability import OperationMetricAvailability
from .operation_metric_specification import OperationMetricSpecification
from .operation_service_specification import OperationServiceSpecification
from .operation import Operation
from .operation_list_response import OperationListResponse
from .azure_data_lake_analytics_linked_service import AzureDataLakeAnalyticsLinkedService
from .hd_insight_on_demand_linked_service import HDInsightOnDemandLinkedService
from .zoho_linked_service import ZohoLinkedService
from .xero_linked_service import XeroLinkedService
from .square_linked_service import SquareLinkedService
from .spark_linked_service import SparkLinkedService
from .shopify_linked_service import ShopifyLinkedService
from .service_now_linked_service import ServiceNowLinkedService
from .quick_books_linked_service import QuickBooksLinkedService
from .presto_linked_service import PrestoLinkedService
from .phoenix_linked_service import PhoenixLinkedService
from .paypal_linked_service import PaypalLinkedService
from .marketo_linked_service import MarketoLinkedService
from .maria_db_linked_service import MariaDBLinkedService
from .magento_linked_service import MagentoLinkedService
from .jira_linked_service import JiraLinkedService
from .impala_linked_service import ImpalaLinkedService
from .hubspot_linked_service import HubspotLinkedService
from .hive_linked_service import HiveLinkedService
from .hbase_linked_service import HBaseLinkedService
from .greenplum_linked_service import GreenplumLinkedService
from .google_big_query_linked_service import GoogleBigQueryLinkedService
from .eloqua_linked_service import EloquaLinkedService
from .drill_linked_service import DrillLinkedService
from .couchbase_linked_service import CouchbaseLinkedService
from .concur_linked_service import ConcurLinkedService
from .azure_postgre_sql_linked_service import AzurePostgreSqlLinkedService
from .amazon_mws_linked_service import AmazonMWSLinkedService
from .sap_hana_linked_service import SapHanaLinkedService
from .sap_bw_linked_service import SapBWLinkedService
from .sftp_server_linked_service import SftpServerLinkedService
from .ftp_server_linked_service import FtpServerLinkedService
from .http_linked_service import HttpLinkedService
from .azure_search_linked_service import AzureSearchLinkedService
from .custom_data_source_linked_service import CustomDataSourceLinkedService
from .amazon_redshift_linked_service import AmazonRedshiftLinkedService
from .amazon_s3_linked_service import AmazonS3LinkedService
from .sap_cloud_for_customer_linked_service import SapCloudForCustomerLinkedService
from .salesforce_linked_service import SalesforceLinkedService
from .azure_data_lake_store_linked_service import AzureDataLakeStoreLinkedService
from .mongo_db_linked_service import MongoDbLinkedService
from .cassandra_linked_service import CassandraLinkedService
from .web_client_certificate_authentication import WebClientCertificateAuthentication
from .web_basic_authentication import WebBasicAuthentication
from .web_anonymous_authentication import WebAnonymousAuthentication
from .web_linked_service_type_properties import WebLinkedServiceTypeProperties
from .web_linked_service import WebLinkedService
from .odata_linked_service import ODataLinkedService
from .hdfs_linked_service import HdfsLinkedService
from .odbc_linked_service import OdbcLinkedService
from .azure_ml_linked_service import AzureMLLinkedService
from .teradata_linked_service import TeradataLinkedService
from .db2_linked_service import Db2LinkedService
from .sybase_linked_service import SybaseLinkedService
from .postgre_sql_linked_service import PostgreSqlLinkedService
from .my_sql_linked_service import MySqlLinkedService
from .azure_my_sql_linked_service import AzureMySqlLinkedService
from .oracle_linked_service import OracleLinkedService
from .file_server_linked_service import FileServerLinkedService
from .hd_insight_linked_service import HDInsightLinkedService
from .dynamics_linked_service import DynamicsLinkedService
from .cosmos_db_linked_service import CosmosDbLinkedService
from .azure_key_vault_linked_service import AzureKeyVaultLinkedService
from .azure_batch_linked_service import AzureBatchLinkedService
from .azure_sql_database_linked_service import AzureSqlDatabaseLinkedService
from .sql_server_linked_service import SqlServerLinkedService
from .azure_sql_dw_linked_service import AzureSqlDWLinkedService
from .azure_storage_linked_service import AzureStorageLinkedService
from .zoho_object_dataset import ZohoObjectDataset
from .xero_object_dataset import XeroObjectDataset
from .square_object_dataset import SquareObjectDataset
from .spark_object_dataset import SparkObjectDataset
from .shopify_object_dataset import ShopifyObjectDataset
from .service_now_object_dataset import ServiceNowObjectDataset
from .quick_books_object_dataset import QuickBooksObjectDataset
from .presto_object_dataset import PrestoObjectDataset
from .phoenix_object_dataset import PhoenixObjectDataset
from .paypal_object_dataset import PaypalObjectDataset
from .marketo_object_dataset import MarketoObjectDataset
from .maria_db_table_dataset import MariaDBTableDataset
from .magento_object_dataset import MagentoObjectDataset
from .jira_object_dataset import JiraObjectDataset
from .impala_object_dataset import ImpalaObjectDataset
from .hubspot_object_dataset import HubspotObjectDataset
from .hive_object_dataset import HiveObjectDataset
from .hbase_object_dataset import HBaseObjectDataset
from .greenplum_table_dataset import GreenplumTableDataset
from .google_big_query_object_dataset import GoogleBigQueryObjectDataset
from .eloqua_object_dataset import EloquaObjectDataset
from .drill_table_dataset import DrillTableDataset
from .couchbase_table_dataset import CouchbaseTableDataset
from .concur_object_dataset import ConcurObjectDataset
from .azure_postgre_sql_table_dataset import AzurePostgreSqlTableDataset
from .amazon_mws_object_dataset import AmazonMWSObjectDataset
from .dataset_zip_deflate_compression import DatasetZipDeflateCompression
from .dataset_deflate_compression import DatasetDeflateCompression
from .dataset_gzip_compression import DatasetGZipCompression
from .dataset_bzip2_compression import DatasetBZip2Compression
from .dataset_compression import DatasetCompression
from .parquet_format import ParquetFormat
from .orc_format import OrcFormat
from .avro_format import AvroFormat
from .json_format import JsonFormat
from .text_format import TextFormat
from .dataset_storage_format import DatasetStorageFormat
from .http_dataset import HttpDataset
from .azure_search_index_dataset import AzureSearchIndexDataset
from .web_table_dataset import WebTableDataset
from .sql_server_table_dataset import SqlServerTableDataset
from .sap_cloud_for_customer_resource_dataset import SapCloudForCustomerResourceDataset
from .salesforce_object_dataset import SalesforceObjectDataset
from .relational_table_dataset import RelationalTableDataset
from .azure_my_sql_table_dataset import AzureMySqlTableDataset
from .oracle_table_dataset import OracleTableDataset
from .odata_resource_dataset import ODataResourceDataset
from .mongo_db_collection_dataset import MongoDbCollectionDataset
from .file_share_dataset import FileShareDataset
from .azure_data_lake_store_dataset import AzureDataLakeStoreDataset
from .dynamics_entity_dataset import DynamicsEntityDataset
from .document_db_collection_dataset import DocumentDbCollectionDataset
from .custom_dataset import CustomDataset
from .cassandra_table_dataset import CassandraTableDataset
from .azure_sql_dw_table_dataset import AzureSqlDWTableDataset
from .azure_sql_table_dataset import AzureSqlTableDataset
from .azure_table_dataset import AzureTableDataset
from .azure_blob_dataset import AzureBlobDataset
from .amazon_s3_dataset import AmazonS3Dataset
from .retry_policy import RetryPolicy
from .tumbling_window_trigger import TumblingWindowTrigger
from .blob_trigger import BlobTrigger
from .recurrence_schedule_occurrence import RecurrenceScheduleOccurrence
from .recurrence_schedule import RecurrenceSchedule
from .schedule_trigger_recurrence import ScheduleTriggerRecurrence
from .schedule_trigger import ScheduleTrigger
from .multiple_pipeline_trigger import MultiplePipelineTrigger
from .activity_policy import ActivityPolicy
from .data_lake_analytics_usql_activity import DataLakeAnalyticsUSQLActivity
from .azure_ml_update_resource_activity import AzureMLUpdateResourceActivity
from .azure_ml_web_service_file import AzureMLWebServiceFile
from .azure_ml_batch_execution_activity import AzureMLBatchExecutionActivity
from .get_metadata_activity import GetMetadataActivity
from .web_activity_authentication import WebActivityAuthentication
from .web_activity import WebActivity
from .redshift_unload_settings import RedshiftUnloadSettings
from .amazon_redshift_source import AmazonRedshiftSource
from .zoho_source import ZohoSource
from .xero_source import XeroSource
from .square_source import SquareSource
from .spark_source import SparkSource
from .shopify_source import ShopifySource
from .service_now_source import ServiceNowSource
from .quick_books_source import QuickBooksSource
from .presto_source import PrestoSource
from .phoenix_source import PhoenixSource
from .paypal_source import PaypalSource
from .marketo_source import MarketoSource
from .maria_db_source import MariaDBSource
from .magento_source import MagentoSource
from .jira_source import JiraSource
from .impala_source import ImpalaSource
from .hubspot_source import HubspotSource
from .hive_source import HiveSource
from .hbase_source import HBaseSource
from .greenplum_source import GreenplumSource
from .google_big_query_source import GoogleBigQuerySource
from .eloqua_source import EloquaSource
from .drill_source import DrillSource
from .couchbase_source import CouchbaseSource
from .concur_source import ConcurSource
from .azure_postgre_sql_source import AzurePostgreSqlSource
from .amazon_mws_source import AmazonMWSSource
from .http_source import HttpSource
from .azure_data_lake_store_source import AzureDataLakeStoreSource
from .mongo_db_source import MongoDbSource
from .cassandra_source import CassandraSource
from .web_source import WebSource
from .oracle_source import OracleSource
from .azure_my_sql_source import AzureMySqlSource
from .distcp_settings import DistcpSettings
from .hdfs_source import HdfsSource
from .file_system_source import FileSystemSource
from .sql_dw_source import SqlDWSource
from .stored_procedure_parameter import StoredProcedureParameter
from .sql_source import SqlSource
from .sap_cloud_for_customer_source import SapCloudForCustomerSource
from .salesforce_source import SalesforceSource
from .relational_source import RelationalSource
from .dynamics_source import DynamicsSource
from .document_db_collection_source import DocumentDbCollectionSource
from .blob_source import BlobSource
from .azure_table_source import AzureTableSource
from .copy_source import CopySource
from .lookup_activity import LookupActivity
from .sql_server_stored_procedure_activity import SqlServerStoredProcedureActivity
from .custom_activity_reference_object import CustomActivityReferenceObject
from .custom_activity import CustomActivity
from .ssis_package_location import SSISPackageLocation
from .execute_ssis_package_activity import ExecuteSSISPackageActivity
from .hd_insight_spark_activity import HDInsightSparkActivity
from .hd_insight_streaming_activity import HDInsightStreamingActivity
from .hd_insight_map_reduce_activity import HDInsightMapReduceActivity
from .hd_insight_pig_activity import HDInsightPigActivity
from .hd_insight_hive_activity import HDInsightHiveActivity
from .redirect_incompatible_row_settings import RedirectIncompatibleRowSettings
from .staging_settings import StagingSettings
from .tabular_translator import TabularTranslator
from .copy_translator import CopyTranslator
from .salesforce_sink import SalesforceSink
from .dynamics_sink import DynamicsSink
from .odbc_sink import OdbcSink
from .azure_search_index_sink import AzureSearchIndexSink
from .azure_data_lake_store_sink import AzureDataLakeStoreSink
from .oracle_sink import OracleSink
from .polybase_settings import PolybaseSettings
from .sql_dw_sink import SqlDWSink
from .sql_sink import SqlSink
from .document_db_collection_sink import DocumentDbCollectionSink
from .file_system_sink import FileSystemSink
from .blob_sink import BlobSink
from .azure_table_sink import AzureTableSink
from .azure_queue_sink import AzureQueueSink
from .sap_cloud_for_customer_sink import SapCloudForCustomerSink
from .copy_sink import CopySink
from .copy_activity import CopyActivity
from .execution_activity import ExecutionActivity
from .until_activity import UntilActivity
from .wait_activity import WaitActivity
from .for_each_activity import ForEachActivity
from .if_condition_activity import IfConditionActivity
from .execute_pipeline_activity import ExecutePipelineActivity
from .control_activity import ControlActivity
from .linked_integration_runtime import LinkedIntegrationRuntime
from .self_hosted_integration_runtime_node import SelfHostedIntegrationRuntimeNode
from .self_hosted_integration_runtime_status import SelfHostedIntegrationRuntimeStatus
from .managed_integration_runtime_operation_result import ManagedIntegrationRuntimeOperationResult
from .managed_integration_runtime_error import ManagedIntegrationRuntimeError
from .managed_integration_runtime_node import ManagedIntegrationRuntimeNode
from .managed_integration_runtime_status import ManagedIntegrationRuntimeStatus
from .linked_integration_runtime_rbac import LinkedIntegrationRuntimeRbac
from .linked_integration_runtime_key import LinkedIntegrationRuntimeKey
from .linked_integration_runtime_properties import LinkedIntegrationRuntimeProperties
from .self_hosted_integration_runtime import SelfHostedIntegrationRuntime
from .integration_runtime_custom_setup_script_properties import IntegrationRuntimeCustomSetupScriptProperties
from .integration_runtime_ssis_catalog_info import IntegrationRuntimeSsisCatalogInfo
from .integration_runtime_ssis_properties import IntegrationRuntimeSsisProperties
from .integration_runtime_vnet_properties import IntegrationRuntimeVNetProperties
from .integration_runtime_compute_properties import IntegrationRuntimeComputeProperties
from .managed_integration_runtime import ManagedIntegrationRuntime
from .integration_runtime_node_ip_address import IntegrationRuntimeNodeIpAddress
from .integration_runtime_node_monitoring_data import IntegrationRuntimeNodeMonitoringData
from .integration_runtime_monitoring_data import IntegrationRuntimeMonitoringData
from .integration_runtime_remove_node_request import IntegrationRuntimeRemoveNodeRequest
from .integration_runtime_auth_keys import IntegrationRuntimeAuthKeys
from .integration_runtime_regenerate_key_parameters import IntegrationRuntimeRegenerateKeyParameters
from .integration_runtime_connection_info import IntegrationRuntimeConnectionInfo
from .factory_paged import FactoryPaged
from .integration_runtime_resource_paged import IntegrationRuntimeResourcePaged
from .linked_service_resource_paged import LinkedServiceResourcePaged
from .dataset_resource_paged import DatasetResourcePaged
from .pipeline_resource_paged import PipelineResourcePaged
from .activity_run_paged import ActivityRunPaged
from .trigger_resource_paged import TriggerResourcePaged
from .trigger_run_paged import TriggerRunPaged
from .data_factory_management_client_enums import (
    IntegrationRuntimeState,
    IntegrationRuntimeAutoUpdate,
    ParameterType,
    DependencyCondition,
    TriggerRuntimeState,
    PipelineRunQueryFilterOperand,
    PipelineRunQueryFilterOperator,
    PipelineRunQueryOrderByField,
    PipelineRunQueryOrder,
    TriggerRunStatus,
    SparkServerType,
    SparkThriftTransportProtocol,
    SparkAuthenticationType,
    ServiceNowAuthenticationType,
    PrestoAuthenticationType,
    PhoenixAuthenticationType,
    ImpalaAuthenticationType,
    HiveServerType,
    HiveThriftTransportProtocol,
    HiveAuthenticationType,
    HBaseAuthenticationType,
    GoogleBigQueryAuthenticationType,
    SapHanaAuthenticationType,
    SftpAuthenticationType,
    FtpAuthenticationType,
    HttpAuthenticationType,
    MongoDbAuthenticationType,
    ODataAuthenticationType,
    TeradataAuthenticationType,
    Db2AuthenticationType,
    SybaseAuthenticationType,
    DatasetCompressionLevel,
    JsonFormatFilePattern,
    TumblingWindowFrequency,
    DayOfWeek,
    DaysOfWeek,
    RecurrenceFrequency,
    WebActivityMethod,
    CassandraSourceReadConsistencyLevels,
    StoredProcedureParameterType,
    SalesforceSourceReadBehavior,
    SSISExecutionRuntime,
    HDInsightActivityDebugInfoOption,
    SalesforceSinkWriteBehavior,
    AzureSearchIndexWriteBehaviorType,
    CopyBehaviorType,
    PolybaseSettingsRejectType,
    SapCloudForCustomerSinkWriteBehavior,
    IntegrationRuntimeType,
    SelfHostedIntegrationRuntimeNodeStatus,
    IntegrationRuntimeUpdateResult,
    IntegrationRuntimeInternalChannelEncryptionMode,
    ManagedIntegrationRuntimeNodeStatus,
    IntegrationRuntimeSsisCatalogPricingTier,
    IntegrationRuntimeLicenseType,
    IntegrationRuntimeEdition,
    IntegrationRuntimeAuthKeyName,
)

__all__ = [
    'Resource',
    'SubResource',
    'Expression',
    'SecureString',
    'LinkedServiceReference',
    'AzureKeyVaultSecretReference',
    'SecretBase',
    'FactoryIdentity',
    'Factory',
    'IntegrationRuntime',
    'IntegrationRuntimeResource',
    'IntegrationRuntimeReference',
    'IntegrationRuntimeStatus',
    'IntegrationRuntimeStatusResponse',
    'IntegrationRuntimeStatusListResponse',
    'UpdateIntegrationRuntimeRequest',
    'UpdateIntegrationRuntimeNodeRequest',
    'LinkedService',
    'LinkedServiceResource',
    'ParameterSpecification',
    'Dataset',
    'DatasetResource',
    'ActivityDependency',
    'Activity',
    'PipelineResource',
    'Trigger',
    'TriggerResource',
    'CreateRunResponse',
    'ErrorResponse', 'ErrorResponseException',
    'PipelineReference',
    'TriggerPipelineReference',
    'FactoryUpdateParameters',
    'DatasetReference',
    'PipelineRunQueryFilter',
    'PipelineRunQueryOrderBy',
    'PipelineRunFilterParameters',
    'PipelineRunInvokedBy',
    'PipelineRun',
    'PipelineRunQueryResponse',
    'ActivityRun',
    'TriggerRun',
    'OperationDisplay',
    'OperationLogSpecification',
    'OperationMetricAvailability',
    'OperationMetricSpecification',
    'OperationServiceSpecification',
    'Operation',
    'OperationListResponse',
    'AzureDataLakeAnalyticsLinkedService',
    'HDInsightOnDemandLinkedService',
    'ZohoLinkedService',
    'XeroLinkedService',
    'SquareLinkedService',
    'SparkLinkedService',
    'ShopifyLinkedService',
    'ServiceNowLinkedService',
    'QuickBooksLinkedService',
    'PrestoLinkedService',
    'PhoenixLinkedService',
    'PaypalLinkedService',
    'MarketoLinkedService',
    'MariaDBLinkedService',
    'MagentoLinkedService',
    'JiraLinkedService',
    'ImpalaLinkedService',
    'HubspotLinkedService',
    'HiveLinkedService',
    'HBaseLinkedService',
    'GreenplumLinkedService',
    'GoogleBigQueryLinkedService',
    'EloquaLinkedService',
    'DrillLinkedService',
    'CouchbaseLinkedService',
    'ConcurLinkedService',
    'AzurePostgreSqlLinkedService',
    'AmazonMWSLinkedService',
    'SapHanaLinkedService',
    'SapBWLinkedService',
    'SftpServerLinkedService',
    'FtpServerLinkedService',
    'HttpLinkedService',
    'AzureSearchLinkedService',
    'CustomDataSourceLinkedService',
    'AmazonRedshiftLinkedService',
    'AmazonS3LinkedService',
    'SapCloudForCustomerLinkedService',
    'SalesforceLinkedService',
    'AzureDataLakeStoreLinkedService',
    'MongoDbLinkedService',
    'CassandraLinkedService',
    'WebClientCertificateAuthentication',
    'WebBasicAuthentication',
    'WebAnonymousAuthentication',
    'WebLinkedServiceTypeProperties',
    'WebLinkedService',
    'ODataLinkedService',
    'HdfsLinkedService',
    'OdbcLinkedService',
    'AzureMLLinkedService',
    'TeradataLinkedService',
    'Db2LinkedService',
    'SybaseLinkedService',
    'PostgreSqlLinkedService',
    'MySqlLinkedService',
    'AzureMySqlLinkedService',
    'OracleLinkedService',
    'FileServerLinkedService',
    'HDInsightLinkedService',
    'DynamicsLinkedService',
    'CosmosDbLinkedService',
    'AzureKeyVaultLinkedService',
    'AzureBatchLinkedService',
    'AzureSqlDatabaseLinkedService',
    'SqlServerLinkedService',
    'AzureSqlDWLinkedService',
    'AzureStorageLinkedService',
    'ZohoObjectDataset',
    'XeroObjectDataset',
    'SquareObjectDataset',
    'SparkObjectDataset',
    'ShopifyObjectDataset',
    'ServiceNowObjectDataset',
    'QuickBooksObjectDataset',
    'PrestoObjectDataset',
    'PhoenixObjectDataset',
    'PaypalObjectDataset',
    'MarketoObjectDataset',
    'MariaDBTableDataset',
    'MagentoObjectDataset',
    'JiraObjectDataset',
    'ImpalaObjectDataset',
    'HubspotObjectDataset',
    'HiveObjectDataset',
    'HBaseObjectDataset',
    'GreenplumTableDataset',
    'GoogleBigQueryObjectDataset',
    'EloquaObjectDataset',
    'DrillTableDataset',
    'CouchbaseTableDataset',
    'ConcurObjectDataset',
    'AzurePostgreSqlTableDataset',
    'AmazonMWSObjectDataset',
    'DatasetZipDeflateCompression',
    'DatasetDeflateCompression',
    'DatasetGZipCompression',
    'DatasetBZip2Compression',
    'DatasetCompression',
    'ParquetFormat',
    'OrcFormat',
    'AvroFormat',
    'JsonFormat',
    'TextFormat',
    'DatasetStorageFormat',
    'HttpDataset',
    'AzureSearchIndexDataset',
    'WebTableDataset',
    'SqlServerTableDataset',
    'SapCloudForCustomerResourceDataset',
    'SalesforceObjectDataset',
    'RelationalTableDataset',
    'AzureMySqlTableDataset',
    'OracleTableDataset',
    'ODataResourceDataset',
    'MongoDbCollectionDataset',
    'FileShareDataset',
    'AzureDataLakeStoreDataset',
    'DynamicsEntityDataset',
    'DocumentDbCollectionDataset',
    'CustomDataset',
    'CassandraTableDataset',
    'AzureSqlDWTableDataset',
    'AzureSqlTableDataset',
    'AzureTableDataset',
    'AzureBlobDataset',
    'AmazonS3Dataset',
    'RetryPolicy',
    'TumblingWindowTrigger',
    'BlobTrigger',
    'RecurrenceScheduleOccurrence',
    'RecurrenceSchedule',
    'ScheduleTriggerRecurrence',
    'ScheduleTrigger',
    'MultiplePipelineTrigger',
    'ActivityPolicy',
    'DataLakeAnalyticsUSQLActivity',
    'AzureMLUpdateResourceActivity',
    'AzureMLWebServiceFile',
    'AzureMLBatchExecutionActivity',
    'GetMetadataActivity',
    'WebActivityAuthentication',
    'WebActivity',
    'RedshiftUnloadSettings',
    'AmazonRedshiftSource',
    'ZohoSource',
    'XeroSource',
    'SquareSource',
    'SparkSource',
    'ShopifySource',
    'ServiceNowSource',
    'QuickBooksSource',
    'PrestoSource',
    'PhoenixSource',
    'PaypalSource',
    'MarketoSource',
    'MariaDBSource',
    'MagentoSource',
    'JiraSource',
    'ImpalaSource',
    'HubspotSource',
    'HiveSource',
    'HBaseSource',
    'GreenplumSource',
    'GoogleBigQuerySource',
    'EloquaSource',
    'DrillSource',
    'CouchbaseSource',
    'ConcurSource',
    'AzurePostgreSqlSource',
    'AmazonMWSSource',
    'HttpSource',
    'AzureDataLakeStoreSource',
    'MongoDbSource',
    'CassandraSource',
    'WebSource',
    'OracleSource',
    'AzureMySqlSource',
    'DistcpSettings',
    'HdfsSource',
    'FileSystemSource',
    'SqlDWSource',
    'StoredProcedureParameter',
    'SqlSource',
    'SapCloudForCustomerSource',
    'SalesforceSource',
    'RelationalSource',
    'DynamicsSource',
    'DocumentDbCollectionSource',
    'BlobSource',
    'AzureTableSource',
    'CopySource',
    'LookupActivity',
    'SqlServerStoredProcedureActivity',
    'CustomActivityReferenceObject',
    'CustomActivity',
    'SSISPackageLocation',
    'ExecuteSSISPackageActivity',
    'HDInsightSparkActivity',
    'HDInsightStreamingActivity',
    'HDInsightMapReduceActivity',
    'HDInsightPigActivity',
    'HDInsightHiveActivity',
    'RedirectIncompatibleRowSettings',
    'StagingSettings',
    'TabularTranslator',
    'CopyTranslator',
    'SalesforceSink',
    'DynamicsSink',
    'OdbcSink',
    'AzureSearchIndexSink',
    'AzureDataLakeStoreSink',
    'OracleSink',
    'PolybaseSettings',
    'SqlDWSink',
    'SqlSink',
    'DocumentDbCollectionSink',
    'FileSystemSink',
    'BlobSink',
    'AzureTableSink',
    'AzureQueueSink',
    'SapCloudForCustomerSink',
    'CopySink',
    'CopyActivity',
    'ExecutionActivity',
    'UntilActivity',
    'WaitActivity',
    'ForEachActivity',
    'IfConditionActivity',
    'ExecutePipelineActivity',
    'ControlActivity',
    'LinkedIntegrationRuntime',
    'SelfHostedIntegrationRuntimeNode',
    'SelfHostedIntegrationRuntimeStatus',
    'ManagedIntegrationRuntimeOperationResult',
    'ManagedIntegrationRuntimeError',
    'ManagedIntegrationRuntimeNode',
    'ManagedIntegrationRuntimeStatus',
    'LinkedIntegrationRuntimeRbac',
    'LinkedIntegrationRuntimeKey',
    'LinkedIntegrationRuntimeProperties',
    'SelfHostedIntegrationRuntime',
    'IntegrationRuntimeCustomSetupScriptProperties',
    'IntegrationRuntimeSsisCatalogInfo',
    'IntegrationRuntimeSsisProperties',
    'IntegrationRuntimeVNetProperties',
    'IntegrationRuntimeComputeProperties',
    'ManagedIntegrationRuntime',
    'IntegrationRuntimeNodeIpAddress',
    'IntegrationRuntimeNodeMonitoringData',
    'IntegrationRuntimeMonitoringData',
    'IntegrationRuntimeRemoveNodeRequest',
    'IntegrationRuntimeAuthKeys',
    'IntegrationRuntimeRegenerateKeyParameters',
    'IntegrationRuntimeConnectionInfo',
    'FactoryPaged',
    'IntegrationRuntimeResourcePaged',
    'LinkedServiceResourcePaged',
    'DatasetResourcePaged',
    'PipelineResourcePaged',
    'ActivityRunPaged',
    'TriggerResourcePaged',
    'TriggerRunPaged',
    'IntegrationRuntimeState',
    'IntegrationRuntimeAutoUpdate',
    'ParameterType',
    'DependencyCondition',
    'TriggerRuntimeState',
    'PipelineRunQueryFilterOperand',
    'PipelineRunQueryFilterOperator',
    'PipelineRunQueryOrderByField',
    'PipelineRunQueryOrder',
    'TriggerRunStatus',
    'SparkServerType',
    'SparkThriftTransportProtocol',
    'SparkAuthenticationType',
    'ServiceNowAuthenticationType',
    'PrestoAuthenticationType',
    'PhoenixAuthenticationType',
    'ImpalaAuthenticationType',
    'HiveServerType',
    'HiveThriftTransportProtocol',
    'HiveAuthenticationType',
    'HBaseAuthenticationType',
    'GoogleBigQueryAuthenticationType',
    'SapHanaAuthenticationType',
    'SftpAuthenticationType',
    'FtpAuthenticationType',
    'HttpAuthenticationType',
    'MongoDbAuthenticationType',
    'ODataAuthenticationType',
    'TeradataAuthenticationType',
    'Db2AuthenticationType',
    'SybaseAuthenticationType',
    'DatasetCompressionLevel',
    'JsonFormatFilePattern',
    'TumblingWindowFrequency',
    'DayOfWeek',
    'DaysOfWeek',
    'RecurrenceFrequency',
    'WebActivityMethod',
    'CassandraSourceReadConsistencyLevels',
    'StoredProcedureParameterType',
    'SalesforceSourceReadBehavior',
    'SSISExecutionRuntime',
    'HDInsightActivityDebugInfoOption',
    'SalesforceSinkWriteBehavior',
    'AzureSearchIndexWriteBehaviorType',
    'CopyBehaviorType',
    'PolybaseSettingsRejectType',
    'SapCloudForCustomerSinkWriteBehavior',
    'IntegrationRuntimeType',
    'SelfHostedIntegrationRuntimeNodeStatus',
    'IntegrationRuntimeUpdateResult',
    'IntegrationRuntimeInternalChannelEncryptionMode',
    'ManagedIntegrationRuntimeNodeStatus',
    'IntegrationRuntimeSsisCatalogPricingTier',
    'IntegrationRuntimeLicenseType',
    'IntegrationRuntimeEdition',
    'IntegrationRuntimeAuthKeyName',
]
