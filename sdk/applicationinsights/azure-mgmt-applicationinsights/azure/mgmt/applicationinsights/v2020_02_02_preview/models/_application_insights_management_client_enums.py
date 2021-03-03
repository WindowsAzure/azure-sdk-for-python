# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class ApplicationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Type of application being monitored.
    """

    WEB = "web"
    OTHER = "other"

class FlowType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Used by the Application Insights system to determine what kind of flow this component was
    created by. This is to be set to 'Bluefield' when creating/updating a component via the REST
    API.
    """

    BLUEFIELD = "Bluefield"

class IngestionMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Indicates the flow of the ingestion.
    """

    APPLICATION_INSIGHTS = "ApplicationInsights"
    APPLICATION_INSIGHTS_WITH_DIAGNOSTIC_SETTINGS = "ApplicationInsightsWithDiagnosticSettings"
    LOG_ANALYTICS = "LogAnalytics"

class PublicNetworkAccessType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The network access type for operating on the Application Insights Component. By default it is
    Enabled
    """

    ENABLED = "Enabled"  #: Enables connectivity to Application Insights through public DNS.
    DISABLED = "Disabled"  #: Disables public connectivity to Application Insights through public DNS.

class PurgeState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Status of the operation represented by the requested Id.
    """

    PENDING = "pending"
    COMPLETED = "completed"

class RequestSource(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Describes what tool created this Application Insights component. Customers using this API
    should set this to the default 'rest'.
    """

    REST = "rest"
