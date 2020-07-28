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

from azure.mgmt.core import ARMPipelineClient
from msrest import Serializer, Deserializer

from azure.profiles import KnownProfiles, ProfileDefinition
from azure.profiles.multiapiclient import MultiApiClientMixin
from ._configuration import MonitorClientConfiguration

class _SDKClient(object):
    def __init__(self, *args, **kwargs):
        """This is a fake class to support current implemetation of MultiApiClientMixin."
        Will be removed in final version of multiapi azure-core based client
        """
        pass

class MonitorClient(MultiApiClientMixin, _SDKClient):
    """Monitor Management Client.

    This ready contains multiple API versions, to help you deal with all of the Azure clouds
    (Azure Stack, Azure Government, Azure China, etc.).
    By default, it uses the latest API version available on public Azure.
    For production, you should stick to a particular api-version and/or profile.
    The profile sets a mapping between an operation group and its API version.
    The api-version parameter sets the default API version if the operation
    group is not described in the profile.

    :param credential: Credential needed for the client to connect to Azure.
    :type credential: ~azure.core.credentials.TokenCredential
    :param subscription_id: The Azure subscription Id.
    :type subscription_id: str
    :param str api_version: API version to use if no profile is provided, or if
     missing in profile.
    :param str base_url: Service URL
    :param profile: A profile definition, from KnownProfiles to dict.
    :type profile: azure.profiles.KnownProfiles
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no Retry-After header is present.
    """

    DEFAULT_API_VERSION = '2019-10-17-preview'
    _PROFILE_TAG = "azure.mgmt.eventhub.MonitorClient"
    LATEST_PROFILE = ProfileDefinition({
        _PROFILE_TAG: {
            None: DEFAULT_API_VERSION,
            'action_groups': '2019-06-01',
            'activity_log_alerts': '2017-04-01',
            'activity_logs': '2015-04-01',
            'alert_rule_incidents': '2016-03-01',
            'alert_rules': '2016-03-01',
            'autoscale_settings': '2015-04-01',
            'baseline': '2018-09-01',
            'baselines': '2019-03-01',
            'diagnostic_settings': '2017-05-01-preview',
            'diagnostic_settings_category': '2017-05-01-preview',
            'event_categories': '2015-04-01',
            'guest_diagnostics_settings': '2018-06-01-preview',
            'guest_diagnostics_settings_association': '2018-06-01-preview',
            'log_profiles': '2016-03-01',
            'metric_alerts': '2018-03-01',
            'metric_alerts_status': '2018-03-01',
            'metric_baseline': '2018-09-01',
            'metric_definitions': '2018-01-01',
            'metric_namespaces': '2017-12-01-preview',
            'metrics': '2018-01-01',
            'operations': '2015-04-01',
            'scheduled_query_rules': '2018-04-16',
            'service_diagnostic_settings': '2016-09-01',
            'tenant_activity_logs': '2015-04-01',
            'vm_insights': '2018-11-27-preview',
        }},
        _PROFILE_TAG + " latest"
    )

    def __init__(
        self,
        credential,  # type: "TokenCredential"
        subscription_id,  # type: str
        api_version=None,
        base_url=None,
        profile=KnownProfiles.default,
        **kwargs  # type: Any
    ):
        if not base_url:
            base_url = 'https://management.azure.com'
        self._config = MonitorClientConfiguration(credential, subscription_id, **kwargs)
        self._client = ARMPipelineClient(base_url=base_url, config=self._config, **kwargs)
        super(MonitorClient, self).__init__(
            credential,
            self._config,
            api_version=api_version,
            profile=profile
        )

    @classmethod
    def _models_dict(cls, api_version):
        return {k: v for k, v in cls.models(api_version).__dict__.items() if isinstance(v, type)}

    @classmethod
    def models(cls, api_version=DEFAULT_API_VERSION):
        """Module depends on the API version:

           * 2015-04-01: :mod:`v2015_04_01.models<azure.mgmt.eventhub.v2015_04_01.models>`
           * 2015-07-01: :mod:`v2015_07_01.models<azure.mgmt.eventhub.v2015_07_01.models>`
           * 2016-03-01: :mod:`v2016_03_01.models<azure.mgmt.eventhub.v2016_03_01.models>`
           * 2016-09-01: :mod:`v2016_09_01.models<azure.mgmt.eventhub.v2016_09_01.models>`
           * 2017-03-01-preview: :mod:`v2017_03_01_preview.models<azure.mgmt.eventhub.v2017_03_01_preview.models>`
           * 2017-04-01: :mod:`v2017_04_01.models<azure.mgmt.eventhub.v2017_04_01.models>`
           * 2017-05-01-preview: :mod:`v2017_05_01_preview.models<azure.mgmt.eventhub.v2017_05_01_preview.models>`
           * 2017-11-01-preview: :mod:`v2017_11_01_preview.models<azure.mgmt.eventhub.v2017_11_01_preview.models>`
           * 2017-12-01-preview: :mod:`v2017_12_01_preview.models<azure.mgmt.eventhub.v2017_12_01_preview.models>`
           * 2018-01-01: :mod:`v2018_01_01.models<azure.mgmt.eventhub.v2018_01_01.models>`
           * 2018-03-01: :mod:`v2018_03_01.models<azure.mgmt.eventhub.v2018_03_01.models>`
           * 2018-04-16: :mod:`v2018_04_16.models<azure.mgmt.eventhub.v2018_04_16.models>`
           * 2018-06-01-preview: :mod:`v2018_06_01_preview.models<azure.mgmt.eventhub.v2018_06_01_preview.models>`
           * 2018-09-01: :mod:`v2018_09_01.models<azure.mgmt.eventhub.v2018_09_01.models>`
           * 2018-11-27-preview: :mod:`v2018_11_27_preview.models<azure.mgmt.eventhub.v2018_11_27_preview.models>`
           * 2019-03-01: :mod:`v2019_03_01.models<azure.mgmt.eventhub.v2019_03_01.models>`
           * 2019-06-01: :mod:`v2019_06_01.models<azure.mgmt.eventhub.v2019_06_01.models>`
           * 2019-10-17-preview: :mod:`v2019_10_17.models<azure.mgmt.eventhub.v2019_10_17.models>`
        """
        if api_version == '2015-04-01':
            from .v2015_04_01 import models
            return models
        elif api_version == '2015-07-01':
            from .v2015_07_01 import models
            return models
        elif api_version == '2016-03-01':
            from .v2016_03_01 import models
            return models
        elif api_version == '2016-09-01':
            from .v2016_09_01 import models
            return models
        elif api_version == '2017-03-01-preview':
            from .v2017_03_01_preview import models
            return models
        elif api_version == '2017-04-01':
            from .v2017_04_01 import models
            return models
        elif api_version == '2017-05-01-preview':
            from .v2017_05_01_preview import models
            return models
        elif api_version == '2017-11-01-preview':
            from .v2017_11_01_preview import models
            return models
        elif api_version == '2017-12-01-preview':
            from .v2017_12_01_preview import models
            return models
        elif api_version == '2018-01-01':
            from .v2018_01_01 import models
            return models
        elif api_version == '2018-03-01':
            from .v2018_03_01 import models
            return models
        elif api_version == '2018-04-16':
            from .v2018_04_16 import models
            return models
        elif api_version == '2018-06-01-preview':
            from .v2018_06_01_preview import models
            return models
        elif api_version == '2018-09-01':
            from .v2018_09_01 import models
            return models
        elif api_version == '2018-11-27-preview':
            from .v2018_11_27_preview import models
            return models
        elif api_version == '2019-03-01':
            from .v2019_03_01 import models
            return models
        elif api_version == '2019-06-01':
            from .v2019_06_01 import models
            return models
        elif api_version == '2019-10-17-preview':
            from .v2019_10_17 import models
            return models
        raise NotImplementedError("APIVersion {} is not available".format(api_version))

    @property
    def action_groups(self):
        """Instance depends on the API version:

           * 2017-04-01: :class:`ActionGroupsOperations<azure.mgmt.eventhub.v2017_04_01.operations.ActionGroupsOperations>`
           * 2018-03-01: :class:`ActionGroupsOperations<azure.mgmt.eventhub.v2018_03_01.operations.ActionGroupsOperations>`
           * 2018-09-01: :class:`ActionGroupsOperations<azure.mgmt.eventhub.v2018_09_01.operations.ActionGroupsOperations>`
           * 2019-03-01: :class:`ActionGroupsOperations<azure.mgmt.eventhub.v2019_03_01.operations.ActionGroupsOperations>`
           * 2019-06-01: :class:`ActionGroupsOperations<azure.mgmt.eventhub.v2019_06_01.operations.ActionGroupsOperations>`
        """
        api_version = self._get_api_version('action_groups')
        if api_version == '2017-04-01':
            from .v2017_04_01.operations import ActionGroupsOperations as OperationClass
        elif api_version == '2018-03-01':
            from .v2018_03_01.operations import ActionGroupsOperations as OperationClass
        elif api_version == '2018-09-01':
            from .v2018_09_01.operations import ActionGroupsOperations as OperationClass
        elif api_version == '2019-03-01':
            from .v2019_03_01.operations import ActionGroupsOperations as OperationClass
        elif api_version == '2019-06-01':
            from .v2019_06_01.operations import ActionGroupsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def activity_log_alerts(self):
        """Instance depends on the API version:

           * 2017-03-01-preview: :class:`ActivityLogAlertsOperations<azure.mgmt.eventhub.v2017_03_01_preview.operations.ActivityLogAlertsOperations>`
           * 2017-04-01: :class:`ActivityLogAlertsOperations<azure.mgmt.eventhub.v2017_04_01.operations.ActivityLogAlertsOperations>`
        """
        api_version = self._get_api_version('activity_log_alerts')
        if api_version == '2017-03-01-preview':
            from .v2017_03_01_preview.operations import ActivityLogAlertsOperations as OperationClass
        elif api_version == '2017-04-01':
            from .v2017_04_01.operations import ActivityLogAlertsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def activity_logs(self):
        """Instance depends on the API version:

           * 2015-04-01: :class:`ActivityLogsOperations<azure.mgmt.eventhub.v2015_04_01.operations.ActivityLogsOperations>`
        """
        api_version = self._get_api_version('activity_logs')
        if api_version == '2015-04-01':
            from .v2015_04_01.operations import ActivityLogsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def alert_rule_incidents(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`AlertRuleIncidentsOperations<azure.mgmt.eventhub.v2016_03_01.operations.AlertRuleIncidentsOperations>`
        """
        api_version = self._get_api_version('alert_rule_incidents')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import AlertRuleIncidentsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def alert_rules(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`AlertRulesOperations<azure.mgmt.eventhub.v2016_03_01.operations.AlertRulesOperations>`
        """
        api_version = self._get_api_version('alert_rules')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import AlertRulesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def autoscale_settings(self):
        """Instance depends on the API version:

           * 2015-04-01: :class:`AutoscaleSettingsOperations<azure.mgmt.eventhub.v2015_04_01.operations.AutoscaleSettingsOperations>`
        """
        api_version = self._get_api_version('autoscale_settings')
        if api_version == '2015-04-01':
            from .v2015_04_01.operations import AutoscaleSettingsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def baseline(self):
        """Instance depends on the API version:

           * 2018-09-01: :class:`BaselineOperations<azure.mgmt.eventhub.v2018_09_01.operations.BaselineOperations>`
        """
        api_version = self._get_api_version('baseline')
        if api_version == '2018-09-01':
            from .v2018_09_01.operations import BaselineOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def baselines(self):
        """Instance depends on the API version:

           * 2019-03-01: :class:`BaselinesOperations<azure.mgmt.eventhub.v2019_03_01.operations.BaselinesOperations>`
        """
        api_version = self._get_api_version('baselines')
        if api_version == '2019-03-01':
            from .v2019_03_01.operations import BaselinesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def diagnostic_settings(self):
        """Instance depends on the API version:

           * 2017-05-01-preview: :class:`DiagnosticSettingsOperations<azure.mgmt.eventhub.v2017_05_01_preview.operations.DiagnosticSettingsOperations>`
        """
        api_version = self._get_api_version('diagnostic_settings')
        if api_version == '2017-05-01-preview':
            from .v2017_05_01_preview.operations import DiagnosticSettingsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def diagnostic_settings_category(self):
        """Instance depends on the API version:

           * 2017-05-01-preview: :class:`DiagnosticSettingsCategoryOperations<azure.mgmt.eventhub.v2017_05_01_preview.operations.DiagnosticSettingsCategoryOperations>`
        """
        api_version = self._get_api_version('diagnostic_settings_category')
        if api_version == '2017-05-01-preview':
            from .v2017_05_01_preview.operations import DiagnosticSettingsCategoryOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def event_categories(self):
        """Instance depends on the API version:

           * 2015-04-01: :class:`EventCategoriesOperations<azure.mgmt.eventhub.v2015_04_01.operations.EventCategoriesOperations>`
        """
        api_version = self._get_api_version('event_categories')
        if api_version == '2015-04-01':
            from .v2015_04_01.operations import EventCategoriesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def guest_diagnostics_settings(self):
        """Instance depends on the API version:

           * 2018-06-01-preview: :class:`GuestDiagnosticsSettingsOperations<azure.mgmt.eventhub.v2018_06_01_preview.operations.GuestDiagnosticsSettingsOperations>`
        """
        api_version = self._get_api_version('guest_diagnostics_settings')
        if api_version == '2018-06-01-preview':
            from .v2018_06_01_preview.operations import GuestDiagnosticsSettingsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def guest_diagnostics_settings_association(self):
        """Instance depends on the API version:

           * 2018-06-01-preview: :class:`GuestDiagnosticsSettingsAssociationOperations<azure.mgmt.eventhub.v2018_06_01_preview.operations.GuestDiagnosticsSettingsAssociationOperations>`
        """
        api_version = self._get_api_version('guest_diagnostics_settings_association')
        if api_version == '2018-06-01-preview':
            from .v2018_06_01_preview.operations import GuestDiagnosticsSettingsAssociationOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def log_profiles(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`LogProfilesOperations<azure.mgmt.eventhub.v2016_03_01.operations.LogProfilesOperations>`
        """
        api_version = self._get_api_version('log_profiles')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import LogProfilesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def metric_alerts(self):
        """Instance depends on the API version:

           * 2018-03-01: :class:`MetricAlertsOperations<azure.mgmt.eventhub.v2018_03_01.operations.MetricAlertsOperations>`
        """
        api_version = self._get_api_version('metric_alerts')
        if api_version == '2018-03-01':
            from .v2018_03_01.operations import MetricAlertsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def metric_alerts_status(self):
        """Instance depends on the API version:

           * 2018-03-01: :class:`MetricAlertsStatusOperations<azure.mgmt.eventhub.v2018_03_01.operations.MetricAlertsStatusOperations>`
        """
        api_version = self._get_api_version('metric_alerts_status')
        if api_version == '2018-03-01':
            from .v2018_03_01.operations import MetricAlertsStatusOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def metric_baseline(self):
        """Instance depends on the API version:

           * 2017-11-01-preview: :class:`MetricBaselineOperations<azure.mgmt.eventhub.v2017_11_01_preview.operations.MetricBaselineOperations>`
           * 2018-09-01: :class:`MetricBaselineOperations<azure.mgmt.eventhub.v2018_09_01.operations.MetricBaselineOperations>`
        """
        api_version = self._get_api_version('metric_baseline')
        if api_version == '2017-11-01-preview':
            from .v2017_11_01_preview.operations import MetricBaselineOperations as OperationClass
        elif api_version == '2018-09-01':
            from .v2018_09_01.operations import MetricBaselineOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def metric_definitions(self):
        """Instance depends on the API version:

           * 2016-03-01: :class:`MetricDefinitionsOperations<azure.mgmt.eventhub.v2016_03_01.operations.MetricDefinitionsOperations>`
           * 2017-05-01-preview: :class:`MetricDefinitionsOperations<azure.mgmt.eventhub.v2017_05_01_preview.operations.MetricDefinitionsOperations>`
           * 2018-01-01: :class:`MetricDefinitionsOperations<azure.mgmt.eventhub.v2018_01_01.operations.MetricDefinitionsOperations>`
        """
        api_version = self._get_api_version('metric_definitions')
        if api_version == '2016-03-01':
            from .v2016_03_01.operations import MetricDefinitionsOperations as OperationClass
        elif api_version == '2017-05-01-preview':
            from .v2017_05_01_preview.operations import MetricDefinitionsOperations as OperationClass
        elif api_version == '2018-01-01':
            from .v2018_01_01.operations import MetricDefinitionsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def metric_namespaces(self):
        """Instance depends on the API version:

           * 2017-12-01-preview: :class:`MetricNamespacesOperations<azure.mgmt.eventhub.v2017_12_01_preview.operations.MetricNamespacesOperations>`
        """
        api_version = self._get_api_version('metric_namespaces')
        if api_version == '2017-12-01-preview':
            from .v2017_12_01_preview.operations import MetricNamespacesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def metrics(self):
        """Instance depends on the API version:

           * 2016-09-01: :class:`MetricsOperations<azure.mgmt.eventhub.v2016_09_01.operations.MetricsOperations>`
           * 2017-05-01-preview: :class:`MetricsOperations<azure.mgmt.eventhub.v2017_05_01_preview.operations.MetricsOperations>`
           * 2018-01-01: :class:`MetricsOperations<azure.mgmt.eventhub.v2018_01_01.operations.MetricsOperations>`
        """
        api_version = self._get_api_version('metrics')
        if api_version == '2016-09-01':
            from .v2016_09_01.operations import MetricsOperations as OperationClass
        elif api_version == '2017-05-01-preview':
            from .v2017_05_01_preview.operations import MetricsOperations as OperationClass
        elif api_version == '2018-01-01':
            from .v2018_01_01.operations import MetricsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def operations(self):
        """Instance depends on the API version:

           * 2015-04-01: :class:`Operations<azure.mgmt.eventhub.v2015_04_01.operations.Operations>`
        """
        api_version = self._get_api_version('operations')
        if api_version == '2015-04-01':
            from .v2015_04_01.operations import Operations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def private_endpoint_connections(self):
        """Instance depends on the API version:

           * 2019-10-17-preview: :class:`PrivateEndpointConnectionsOperations<azure.mgmt.eventhub.v2019_10_17.operations.PrivateEndpointConnectionsOperations>`
        """
        api_version = self._get_api_version('private_endpoint_connections')
        if api_version == '2019-10-17-preview':
            from .v2019_10_17.operations import PrivateEndpointConnectionsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def private_link_resources(self):
        """Instance depends on the API version:

           * 2019-10-17-preview: :class:`PrivateLinkResourcesOperations<azure.mgmt.eventhub.v2019_10_17.operations.PrivateLinkResourcesOperations>`
        """
        api_version = self._get_api_version('private_link_resources')
        if api_version == '2019-10-17-preview':
            from .v2019_10_17.operations import PrivateLinkResourcesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def private_link_scope_operation_status(self):
        """Instance depends on the API version:

           * 2019-10-17-preview: :class:`PrivateLinkScopeOperationStatusOperations<azure.mgmt.eventhub.v2019_10_17.operations.PrivateLinkScopeOperationStatusOperations>`
        """
        api_version = self._get_api_version('private_link_scope_operation_status')
        if api_version == '2019-10-17-preview':
            from .v2019_10_17.operations import PrivateLinkScopeOperationStatusOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def private_link_scoped_resources(self):
        """Instance depends on the API version:

           * 2019-10-17-preview: :class:`PrivateLinkScopedResourcesOperations<azure.mgmt.eventhub.v2019_10_17.operations.PrivateLinkScopedResourcesOperations>`
        """
        api_version = self._get_api_version('private_link_scoped_resources')
        if api_version == '2019-10-17-preview':
            from .v2019_10_17.operations import PrivateLinkScopedResourcesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def private_link_scopes(self):
        """Instance depends on the API version:

           * 2019-10-17-preview: :class:`PrivateLinkScopesOperations<azure.mgmt.eventhub.v2019_10_17.operations.PrivateLinkScopesOperations>`
        """
        api_version = self._get_api_version('private_link_scopes')
        if api_version == '2019-10-17-preview':
            from .v2019_10_17.operations import PrivateLinkScopesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def scheduled_query_rules(self):
        """Instance depends on the API version:

           * 2018-04-16: :class:`ScheduledQueryRulesOperations<azure.mgmt.eventhub.v2018_04_16.operations.ScheduledQueryRulesOperations>`
        """
        api_version = self._get_api_version('scheduled_query_rules')
        if api_version == '2018-04-16':
            from .v2018_04_16.operations import ScheduledQueryRulesOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def service_diagnostic_settings(self):
        """Instance depends on the API version:

           * 2015-07-01: :class:`ServiceDiagnosticSettingsOperations<azure.mgmt.eventhub.v2015_07_01.operations.ServiceDiagnosticSettingsOperations>`
           * 2016-09-01: :class:`ServiceDiagnosticSettingsOperations<azure.mgmt.eventhub.v2016_09_01.operations.ServiceDiagnosticSettingsOperations>`
        """
        api_version = self._get_api_version('service_diagnostic_settings')
        if api_version == '2015-07-01':
            from .v2015_07_01.operations import ServiceDiagnosticSettingsOperations as OperationClass
        elif api_version == '2016-09-01':
            from .v2016_09_01.operations import ServiceDiagnosticSettingsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def tenant_activity_logs(self):
        """Instance depends on the API version:

           * 2015-04-01: :class:`TenantActivityLogsOperations<azure.mgmt.eventhub.v2015_04_01.operations.TenantActivityLogsOperations>`
        """
        api_version = self._get_api_version('tenant_activity_logs')
        if api_version == '2015-04-01':
            from .v2015_04_01.operations import TenantActivityLogsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    @property
    def vm_insights(self):
        """Instance depends on the API version:

           * 2018-11-27-preview: :class:`VMInsightsOperations<azure.mgmt.eventhub.v2018_11_27_preview.operations.VMInsightsOperations>`
        """
        api_version = self._get_api_version('vm_insights')
        if api_version == '2018-11-27-preview':
            from .v2018_11_27_preview.operations import VMInsightsOperations as OperationClass
        else:
            raise NotImplementedError("APIVersion {} is not available".format(api_version))
        return OperationClass(self._client, self._config, Serializer(self._models_dict(api_version)), Deserializer(self._models_dict(api_version)))

    def close(self):
        self._client.close()
    def __enter__(self):
        self._client.__enter__()
        return self
    def __exit__(self, *exc_details):
        self._client.__exit__(*exc_details)
