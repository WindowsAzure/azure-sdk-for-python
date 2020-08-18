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

from enum import Enum


class ApplicationType(str, Enum):

    web = "web"
    other = "other"


class FlowType(str, Enum):

    bluefield = "Bluefield"


class RequestSource(str, Enum):

    rest = "rest"


class PublicNetworkAccessType(str, Enum):

    enabled = "Enabled"  #: Enables connectivity to Application Insights through public DNS.
    disabled = "Disabled"  #: Disables public connectivity to Application Insights through public DNS.


class IngestionMode(str, Enum):

    application_insights = "ApplicationInsights"
    application_insights_with_diagnostic_settings = "ApplicationInsightsWithDiagnosticSettings"
    log_analytics = "LogAnalytics"


class PurgeState(str, Enum):

    pending = "pending"
    completed = "completed"
