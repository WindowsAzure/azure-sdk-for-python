# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

from .._generated.models._azure_cognitive_service_metrics_advisor_restapi_open_ap_iv2_enums import (
    SnoozeScope,
    Severity as AnomalySeverity,
    DataSourceType,
    ViewMode as DataFeedAccessMode,
    RollUpMethod as DataFeedAutoRollupMethod,
    FillMissingPointType as DataSourceMissingDataPointFillType,
    AnomalyDetectorDirection,
    IncidentStatus as AnomalyIncidentStatus,
    Granularity as DataFeedGranularityType,
    EntityStatus as DataFeedStatus,
    AnomalyValue,
    ChangePointValue,
    PeriodType,
    FeedbackType,
    TimeMode as AlertQueryTimeMode,
    DataSourceCredentialType
)

from .._generated.models import (
    FeedbackQueryTimeMode,
    RootCause,
    DetectionAnomalyFilterCondition,
    DimensionGroupIdentity,
    DetectionIncidentFilterCondition,
    EnrichmentStatus,
    MetricSeriesItem as MetricSeriesDefinition,
    IngestionStatus as DataFeedIngestionStatus,
    SeriesIdentity,
    SeverityFilterCondition
)

from ._models import (
    AnomalyFeedback,
    ChangePointFeedback,
    CommentFeedback,
    PeriodFeedback,
    MetricAnomalyAlertConfigurationsOperator,
    DataFeedGranularity,
    DataFeedIngestionSettings,
    DataFeedOptions,
    DataFeedMissingDataPointFillSettings,
    DataFeedRollupSettings,
    DataFeedSchema,
    DataFeed,
    MetricAnomalyAlertScope,
    MetricAlertConfiguration,
    AzureApplicationInsightsDataFeedSource,
    AzureBlobDataFeedSource,
    AzureCosmosDBDataFeedSource,
    AzureTableDataFeedSource,
    AzureLogAnalyticsDataFeedSource,
    InfluxDBDataFeedSource,
    SQLServerDataFeedSource,
    MongoDBDataFeedSource,
    MySqlDataFeedSource,
    PostgreSqlDataFeedSource,
    AzureDataExplorerDataFeedSource,
    AnomalyAlertConfiguration,
    NotificationHook,
    EmailNotificationHook,
    WebNotificationHook,
    TopNGroupScope,
    SeverityCondition,
    MetricAnomalyAlertSnoozeCondition,
    MetricBoundaryCondition,
    MetricDetectionCondition,
    MetricSeriesGroupDetectionCondition,
    SmartDetectionCondition,
    HardThresholdCondition,
    SuppressCondition,
    ChangeThresholdCondition,
    MetricSingleSeriesDetectionCondition,
    DataFeedDimension,
    DataFeedMetric,
    DataFeedIngestionProgress,
    DetectionConditionsOperator,
    AnomalyDetectionConfiguration,
    MetricAnomalyAlertConditions,
    AnomalyIncident,
    DataPointAnomaly,
    MetricSeriesData,
    AnomalyAlert,
    AzureDataLakeStorageGen2DataFeedSource,
    AzureEventHubsDataFeedSource,
    MetricAnomalyAlertScopeType,
    DataFeedRollupType,
    IncidentRootCause,
    MetricEnrichedSeriesData,
    SQLConnectionStringCredentialEntity,
    DataLakeGen2SharedKeyCredentialEntity,
    ServicePrincipalCredentialEntity,
    ServicePrincipalInKVCredentialEntity,
)


__all__ = (
    "AnomalyFeedback",
    "ChangePointFeedback",
    "CommentFeedback",
    "PeriodFeedback",
    "FeedbackQueryTimeMode",
    "RootCause",
    "AnomalyAlertConfiguration",
    "DetectionAnomalyFilterCondition",
    "DimensionGroupIdentity",
    "AnomalyIncident",
    "DetectionIncidentFilterCondition",
    "AnomalyDetectionConfiguration",
    "MetricAnomalyAlertConfigurationsOperator",
    "DataFeedStatus",
    "DataFeedGranularity",
    "DataFeedIngestionSettings",
    "DataFeedOptions",
    "DataFeedMissingDataPointFillSettings",
    "DataFeedRollupSettings",
    "DataFeedSchema",
    "DataFeedDimension",
    "DataFeedMetric",
    "DataFeed",
    "TopNGroupScope",
    "MetricAnomalyAlertScope",
    "MetricAlertConfiguration",
    "SnoozeScope",
    "AnomalySeverity",
    "MetricAnomalyAlertSnoozeCondition",
    "MetricBoundaryCondition",
    "AzureApplicationInsightsDataFeedSource",
    "AzureBlobDataFeedSource",
    "AzureCosmosDBDataFeedSource",
    "AzureTableDataFeedSource",
    "AzureLogAnalyticsDataFeedSource",
    "InfluxDBDataFeedSource",
    "SQLServerDataFeedSource",
    "MongoDBDataFeedSource",
    "MySqlDataFeedSource",
    "PostgreSqlDataFeedSource",
    "AzureDataExplorerDataFeedSource",
    "MetricDetectionCondition",
    "MetricSeriesGroupDetectionCondition",
    "MetricSingleSeriesDetectionCondition",
    "SeverityCondition",
    "DataSourceType",
    "MetricAnomalyAlertScopeType",
    "AnomalyDetectorDirection",
    "NotificationHook",
    "EmailNotificationHook",
    "WebNotificationHook",
    "DataFeedIngestionProgress",
    "DetectionConditionsOperator",
    "MetricAnomalyAlertConditions",
    "EnrichmentStatus",
    "DataFeedGranularityType",
    "DataPointAnomaly",
    "AnomalyIncidentStatus",
    "MetricSeriesData",
    "MetricSeriesDefinition",
    "AnomalyAlert",
    "DataFeedAccessMode",
    "DataFeedRollupType",
    "DataFeedAutoRollupMethod",
    "DataSourceMissingDataPointFillType",
    "DataFeedIngestionStatus",
    "SmartDetectionCondition",
    "SuppressCondition",
    "ChangeThresholdCondition",
    "HardThresholdCondition",
    "SeriesIdentity",
    "AzureDataLakeStorageGen2DataFeedSource",
    "AzureEventHubsDataFeedSource",
    "AnomalyValue",
    "ChangePointValue",
    "PeriodType",
    "FeedbackType",
    "AlertQueryTimeMode",
    "IncidentRootCause",
    "SeverityFilterCondition",
    "MetricEnrichedSeriesData",
    "SQLConnectionStringCredentialEntity",
    "DataLakeGen2SharedKeyCredentialEntity",
    "ServicePrincipalCredentialEntity",
    "ServicePrincipalInKVCredentialEntity",
    "DataSourceCredentialType"
)
