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


class ServiceProperties(Model):
    """The service properties for a given service.

    :param id: The id of the service.
    :type id: str
    :param active_alerts: The count of alerts that are currently active for
     the service.
    :type active_alerts: int
    :param additional_information: The additional information related to the
     service.
    :type additional_information: str
    :param created_date: The date and time, in UTC, when the service was
     onboarded to Azure Active Directory Connect Health.
    :type created_date: datetime
    :param custom_notification_emails: The list of additional emails that are
     configured to receive notifications about the service.
    :type custom_notification_emails: list[str]
    :param disabled: Indicates if the service is disabled or not.
    :type disabled: bool
    :param display_name: The display name of the service.
    :type display_name: str
    :param health: The health of the service.
    :type health: str
    :param last_disabled: The date and time, in UTC, when the service was last
     disabled.
    :type last_disabled: datetime
    :param last_updated: The date or time , in UTC, when the service
     properties were last updated.
    :type last_updated: datetime
    :param monitoring_configurations_computed: The monitoring configuration of
     the service which determines what activities are monitored by Azure Active
     Directory Connect Health.
    :type monitoring_configurations_computed: object
    :param monitoring_configurations_customized: The customized monitoring
     configuration of the service which determines what activities are
     monitored by Azure Active Directory Connect Health.
    :type monitoring_configurations_customized: object
    :param notification_email_enabled: Indicates if email notification is
     enabled or not.
    :type notification_email_enabled: bool
    :param notification_email_enabled_for_global_admins: Indicates if email
     notification is enabled for global administrators of the tenant.
    :type notification_email_enabled_for_global_admins: bool
    :param notification_emails_enabled_for_global_admins: Indicates if email
     notification is enabled for global administrators of the tenant.
    :type notification_emails_enabled_for_global_admins: bool
    :param notification_emails: The list of emails to whom service
     notifications will be sent.
    :type notification_emails: list[str]
    :param original_disabled_state: Gets the original disable state.
    :type original_disabled_state: bool
    :param resolved_alerts: The total count of alerts that has been resolved
     for the service.
    :type resolved_alerts: int
    :param service_id: The id of the service.
    :type service_id: str
    :param service_name: The name of the service.
    :type service_name: str
    :param signature: The signature of the service.
    :type signature: str
    :param simple_properties: List of service specific configuration
     properties.
    :type simple_properties: object
    :param tenant_id: The id of the tenant to which the service is registered
     to.
    :type tenant_id: str
    :param type: The service type for the services onboarded to Azure Active
     Directory Connect Health. Depending on whether the service is monitoring,
     ADFS, Sync or ADDS roles, the service type can either be
     AdFederationService or AadSyncService or AdDomainService.
    :type type: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'active_alerts': {'key': 'activeAlerts', 'type': 'int'},
        'additional_information': {'key': 'additionalInformation', 'type': 'str'},
        'created_date': {'key': 'createdDate', 'type': 'iso-8601'},
        'custom_notification_emails': {'key': 'customNotificationEmails', 'type': '[str]'},
        'disabled': {'key': 'disabled', 'type': 'bool'},
        'display_name': {'key': 'displayName', 'type': 'str'},
        'health': {'key': 'health', 'type': 'str'},
        'last_disabled': {'key': 'lastDisabled', 'type': 'iso-8601'},
        'last_updated': {'key': 'lastUpdated', 'type': 'iso-8601'},
        'monitoring_configurations_computed': {'key': 'monitoringConfigurationsComputed', 'type': 'object'},
        'monitoring_configurations_customized': {'key': 'monitoringConfigurationsCustomized', 'type': 'object'},
        'notification_email_enabled': {'key': 'notificationEmailEnabled', 'type': 'bool'},
        'notification_email_enabled_for_global_admins': {'key': 'notificationEmailEnabledForGlobalAdmins', 'type': 'bool'},
        'notification_emails_enabled_for_global_admins': {'key': 'notificationEmailsEnabledForGlobalAdmins', 'type': 'bool'},
        'notification_emails': {'key': 'notificationEmails', 'type': '[str]'},
        'original_disabled_state': {'key': 'originalDisabledState', 'type': 'bool'},
        'resolved_alerts': {'key': 'resolvedAlerts', 'type': 'int'},
        'service_id': {'key': 'serviceId', 'type': 'str'},
        'service_name': {'key': 'serviceName', 'type': 'str'},
        'signature': {'key': 'signature', 'type': 'str'},
        'simple_properties': {'key': 'simpleProperties', 'type': 'object'},
        'tenant_id': {'key': 'tenantId', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ServiceProperties, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.active_alerts = kwargs.get('active_alerts', None)
        self.additional_information = kwargs.get('additional_information', None)
        self.created_date = kwargs.get('created_date', None)
        self.custom_notification_emails = kwargs.get('custom_notification_emails', None)
        self.disabled = kwargs.get('disabled', None)
        self.display_name = kwargs.get('display_name', None)
        self.health = kwargs.get('health', None)
        self.last_disabled = kwargs.get('last_disabled', None)
        self.last_updated = kwargs.get('last_updated', None)
        self.monitoring_configurations_computed = kwargs.get('monitoring_configurations_computed', None)
        self.monitoring_configurations_customized = kwargs.get('monitoring_configurations_customized', None)
        self.notification_email_enabled = kwargs.get('notification_email_enabled', None)
        self.notification_email_enabled_for_global_admins = kwargs.get('notification_email_enabled_for_global_admins', None)
        self.notification_emails_enabled_for_global_admins = kwargs.get('notification_emails_enabled_for_global_admins', None)
        self.notification_emails = kwargs.get('notification_emails', None)
        self.original_disabled_state = kwargs.get('original_disabled_state', None)
        self.resolved_alerts = kwargs.get('resolved_alerts', None)
        self.service_id = kwargs.get('service_id', None)
        self.service_name = kwargs.get('service_name', None)
        self.signature = kwargs.get('signature', None)
        self.simple_properties = kwargs.get('simple_properties', None)
        self.tenant_id = kwargs.get('tenant_id', None)
        self.type = kwargs.get('type', None)
