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

import uuid
from msrest.pipeline import ClientRawResponse

from .. import models


class ActionRulesOperations(object):
    """ActionRulesOperations operations.

    You should not instantiate directly this class, but create a Client instance that will create it for you and attach it as attribute.

    :param client: Client for service requests.
    :param config: Configuration of service client.
    :param serializer: An object model serializer.
    :param deserializer: An object model deserializer.
    :ivar api_version: client API version. Constant value: "2019-05-05-preview".
    """

    models = models

    def __init__(self, client, config, serializer, deserializer):

        self._client = client
        self._serialize = serializer
        self._deserialize = deserializer
        self.api_version = "2019-05-05-preview"

        self.config = config

    def list_by_subscription(
            self, target_resource_group=None, target_resource_type=None, target_resource=None, severity=None, monitor_service=None, impacted_scope=None, description=None, alert_rule_id=None, action_group=None, name=None, custom_headers=None, raw=False, **operation_config):
        """Get all action rule in a given subscription.

        List all action rules of the subscription and given input filters.

        :param target_resource_group: Filter by target resource group name.
         Default value is select all.
        :type target_resource_group: str
        :param target_resource_type: Filter by target resource type. Default
         value is select all.
        :type target_resource_type: str
        :param target_resource: Filter by target resource( which is full ARM
         ID) Default value is select all.
        :type target_resource: str
        :param severity: Filter by severity.  Default value is select all.
         Possible values include: 'Sev0', 'Sev1', 'Sev2', 'Sev3', 'Sev4'
        :type severity: str or ~azure.mgmt.alertsmanagement.models.Severity
        :param monitor_service: Filter by monitor service which generates the
         alert instance. Default value is select all. Possible values include:
         'Application Insights', 'ActivityLog Administrative', 'ActivityLog
         Security', 'ActivityLog Recommendation', 'ActivityLog Policy',
         'ActivityLog Autoscale', 'Log Analytics', 'Nagios', 'Platform',
         'SCOM', 'ServiceHealth', 'SmartDetector', 'VM Insights', 'Zabbix'
        :type monitor_service: str or
         ~azure.mgmt.alertsmanagement.models.MonitorService
        :param impacted_scope: filter by impacted/target scope (provide comma
         separated list for multiple scopes). The value should be an well
         constructed ARM id of the scope.
        :type impacted_scope: str
        :param description: filter by alert rule description
        :type description: str
        :param alert_rule_id: filter by alert rule id
        :type alert_rule_id: str
        :param action_group: filter by action group configured as part of
         action rule
        :type action_group: str
        :param name: filter by action rule name
        :type name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ActionRule
        :rtype:
         ~azure.mgmt.alertsmanagement.models.ActionRulePaged[~azure.mgmt.alertsmanagement.models.ActionRule]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.alertsmanagement.models.ErrorResponseException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_by_subscription.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str', min_length=1)
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if target_resource_group is not None:
                    query_parameters['targetResourceGroup'] = self._serialize.query("target_resource_group", target_resource_group, 'str')
                if target_resource_type is not None:
                    query_parameters['targetResourceType'] = self._serialize.query("target_resource_type", target_resource_type, 'str')
                if target_resource is not None:
                    query_parameters['targetResource'] = self._serialize.query("target_resource", target_resource, 'str')
                if severity is not None:
                    query_parameters['severity'] = self._serialize.query("severity", severity, 'str')
                if monitor_service is not None:
                    query_parameters['monitorService'] = self._serialize.query("monitor_service", monitor_service, 'str')
                if impacted_scope is not None:
                    query_parameters['impactedScope'] = self._serialize.query("impacted_scope", impacted_scope, 'str')
                if description is not None:
                    query_parameters['description'] = self._serialize.query("description", description, 'str')
                if alert_rule_id is not None:
                    query_parameters['alertRuleId'] = self._serialize.query("alert_rule_id", alert_rule_id, 'str')
                if action_group is not None:
                    query_parameters['actionGroup'] = self._serialize.query("action_group", action_group, 'str')
                if name is not None:
                    query_parameters['name'] = self._serialize.query("name", name, 'str')
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.ActionRulePaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_by_subscription.metadata = {'url': '/subscriptions/{subscriptionId}/providers/Microsoft.AlertsManagement/actionRules'}

    def list_by_resource_group(
            self, resource_group_name, target_resource_group=None, target_resource_type=None, target_resource=None, severity=None, monitor_service=None, impacted_scope=None, description=None, alert_rule_id=None, action_group=None, name=None, custom_headers=None, raw=False, **operation_config):
        """Get all action rules created in a resource group.

        List all action rules of the subscription, created in given resource
        group and given input filters.

        :param resource_group_name: Resource group name where the resource is
         created.
        :type resource_group_name: str
        :param target_resource_group: Filter by target resource group name.
         Default value is select all.
        :type target_resource_group: str
        :param target_resource_type: Filter by target resource type. Default
         value is select all.
        :type target_resource_type: str
        :param target_resource: Filter by target resource( which is full ARM
         ID) Default value is select all.
        :type target_resource: str
        :param severity: Filter by severity.  Default value is select all.
         Possible values include: 'Sev0', 'Sev1', 'Sev2', 'Sev3', 'Sev4'
        :type severity: str or ~azure.mgmt.alertsmanagement.models.Severity
        :param monitor_service: Filter by monitor service which generates the
         alert instance. Default value is select all. Possible values include:
         'Application Insights', 'ActivityLog Administrative', 'ActivityLog
         Security', 'ActivityLog Recommendation', 'ActivityLog Policy',
         'ActivityLog Autoscale', 'Log Analytics', 'Nagios', 'Platform',
         'SCOM', 'ServiceHealth', 'SmartDetector', 'VM Insights', 'Zabbix'
        :type monitor_service: str or
         ~azure.mgmt.alertsmanagement.models.MonitorService
        :param impacted_scope: filter by impacted/target scope (provide comma
         separated list for multiple scopes). The value should be an well
         constructed ARM id of the scope.
        :type impacted_scope: str
        :param description: filter by alert rule description
        :type description: str
        :param alert_rule_id: filter by alert rule id
        :type alert_rule_id: str
        :param action_group: filter by action group configured as part of
         action rule
        :type action_group: str
        :param name: filter by action rule name
        :type name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: An iterator like instance of ActionRule
        :rtype:
         ~azure.mgmt.alertsmanagement.models.ActionRulePaged[~azure.mgmt.alertsmanagement.models.ActionRule]
        :raises:
         :class:`ErrorResponseException<azure.mgmt.alertsmanagement.models.ErrorResponseException>`
        """
        def prepare_request(next_link=None):
            if not next_link:
                # Construct URL
                url = self.list_by_resource_group.metadata['url']
                path_format_arguments = {
                    'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str', min_length=1),
                    'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str')
                }
                url = self._client.format_url(url, **path_format_arguments)

                # Construct parameters
                query_parameters = {}
                if target_resource_group is not None:
                    query_parameters['targetResourceGroup'] = self._serialize.query("target_resource_group", target_resource_group, 'str')
                if target_resource_type is not None:
                    query_parameters['targetResourceType'] = self._serialize.query("target_resource_type", target_resource_type, 'str')
                if target_resource is not None:
                    query_parameters['targetResource'] = self._serialize.query("target_resource", target_resource, 'str')
                if severity is not None:
                    query_parameters['severity'] = self._serialize.query("severity", severity, 'str')
                if monitor_service is not None:
                    query_parameters['monitorService'] = self._serialize.query("monitor_service", monitor_service, 'str')
                if impacted_scope is not None:
                    query_parameters['impactedScope'] = self._serialize.query("impacted_scope", impacted_scope, 'str')
                if description is not None:
                    query_parameters['description'] = self._serialize.query("description", description, 'str')
                if alert_rule_id is not None:
                    query_parameters['alertRuleId'] = self._serialize.query("alert_rule_id", alert_rule_id, 'str')
                if action_group is not None:
                    query_parameters['actionGroup'] = self._serialize.query("action_group", action_group, 'str')
                if name is not None:
                    query_parameters['name'] = self._serialize.query("name", name, 'str')
                query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

            else:
                url = next_link
                query_parameters = {}

            # Construct headers
            header_parameters = {}
            header_parameters['Accept'] = 'application/json'
            if self.config.generate_client_request_id:
                header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
            if custom_headers:
                header_parameters.update(custom_headers)
            if self.config.accept_language is not None:
                header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

            # Construct and send request
            request = self._client.get(url, query_parameters, header_parameters)
            return request

        def internal_paging(next_link=None):
            request = prepare_request(next_link)

            response = self._client.send(request, stream=False, **operation_config)

            if response.status_code not in [200]:
                raise models.ErrorResponseException(self._deserialize, response)

            return response

        # Deserialize response
        header_dict = None
        if raw:
            header_dict = {}
        deserialized = models.ActionRulePaged(internal_paging, self._deserialize.dependencies, header_dict)

        return deserialized
    list_by_resource_group.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AlertsManagement/actionRules'}

    def get_by_name(
            self, resource_group_name, action_rule_name, custom_headers=None, raw=False, **operation_config):
        """Get action rule by name.

        Get a specific action rule.

        :param resource_group_name: Resource group name where the resource is
         created.
        :type resource_group_name: str
        :param action_rule_name: The name of action rule that needs to be
         fetched
        :type action_rule_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ActionRule or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.alertsmanagement.models.ActionRule or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.alertsmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.get_by_name.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str', min_length=1),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'actionRuleName': self._serialize.url("action_rule_name", action_rule_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.get(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        header_dict = {}
        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('ActionRule', response)
            header_dict = {
                'x-ms-request-id': 'str',
            }

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            client_raw_response.add_headers(header_dict)
            return client_raw_response

        return deserialized
    get_by_name.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AlertsManagement/actionRules/{actionRuleName}'}

    def create_update(
            self, resource_group_name, action_rule_name, action_rule, custom_headers=None, raw=False, **operation_config):
        """Create/update an action rule.

        Creates/Updates a specific action rule.

        :param resource_group_name: Resource group name where the resource is
         created.
        :type resource_group_name: str
        :param action_rule_name: The name of action rule that needs to be
         created/updated
        :type action_rule_name: str
        :param action_rule: action rule to be created/updated
        :type action_rule: ~azure.mgmt.alertsmanagement.models.ActionRule
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ActionRule or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.alertsmanagement.models.ActionRule or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.alertsmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.create_update.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str', min_length=1),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'actionRuleName': self._serialize.url("action_rule_name", action_rule_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(action_rule, 'ActionRule')

        # Construct and send request
        request = self._client.put(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        header_dict = {}
        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('ActionRule', response)
            header_dict = {
                'x-ms-request-id': 'str',
            }

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            client_raw_response.add_headers(header_dict)
            return client_raw_response

        return deserialized
    create_update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AlertsManagement/actionRules/{actionRuleName}'}

    def delete(
            self, resource_group_name, action_rule_name, custom_headers=None, raw=False, **operation_config):
        """Delete action rule.

        Deletes a given action rule.

        :param resource_group_name: Resource group name where the resource is
         created.
        :type resource_group_name: str
        :param action_rule_name: The name that needs to be deleted
        :type action_rule_name: str
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: bool or ClientRawResponse if raw=true
        :rtype: bool or ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.alertsmanagement.models.ErrorResponseException>`
        """
        # Construct URL
        url = self.delete.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str', min_length=1),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'actionRuleName': self._serialize.url("action_rule_name", action_rule_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct and send request
        request = self._client.delete(url, query_parameters, header_parameters)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        header_dict = {}
        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('bool', response)
            header_dict = {
                'x-ms-request-id': 'str',
            }

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            client_raw_response.add_headers(header_dict)
            return client_raw_response

        return deserialized
    delete.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AlertsManagement/actionRules/{actionRuleName}'}

    def update(
            self, resource_group_name, action_rule_name, status=None, tags=None, custom_headers=None, raw=False, **operation_config):
        """Patch action rule.

        Update enabled flag and/or tags for the given action rule.

        :param resource_group_name: Resource group name where the resource is
         created.
        :type resource_group_name: str
        :param action_rule_name: The name that needs to be updated
        :type action_rule_name: str
        :param status: Indicates if the given action rule is enabled or
         disabled. Possible values include: 'Enabled', 'Disabled'
        :type status: str or
         ~azure.mgmt.alertsmanagement.models.ActionRuleStatus
        :param tags: tags to be updated
        :type tags: object
        :param dict custom_headers: headers that will be added to the request
        :param bool raw: returns the direct response alongside the
         deserialized response
        :param operation_config: :ref:`Operation configuration
         overrides<msrest:optionsforoperations>`.
        :return: ActionRule or ClientRawResponse if raw=true
        :rtype: ~azure.mgmt.alertsmanagement.models.ActionRule or
         ~msrest.pipeline.ClientRawResponse
        :raises:
         :class:`ErrorResponseException<azure.mgmt.alertsmanagement.models.ErrorResponseException>`
        """
        action_rule_patch = models.PatchObject(status=status, tags=tags)

        # Construct URL
        url = self.update.metadata['url']
        path_format_arguments = {
            'subscriptionId': self._serialize.url("self.config.subscription_id", self.config.subscription_id, 'str', min_length=1),
            'resourceGroupName': self._serialize.url("resource_group_name", resource_group_name, 'str'),
            'actionRuleName': self._serialize.url("action_rule_name", action_rule_name, 'str')
        }
        url = self._client.format_url(url, **path_format_arguments)

        # Construct parameters
        query_parameters = {}
        query_parameters['api-version'] = self._serialize.query("self.api_version", self.api_version, 'str')

        # Construct headers
        header_parameters = {}
        header_parameters['Accept'] = 'application/json'
        header_parameters['Content-Type'] = 'application/json; charset=utf-8'
        if self.config.generate_client_request_id:
            header_parameters['x-ms-client-request-id'] = str(uuid.uuid1())
        if custom_headers:
            header_parameters.update(custom_headers)
        if self.config.accept_language is not None:
            header_parameters['accept-language'] = self._serialize.header("self.config.accept_language", self.config.accept_language, 'str')

        # Construct body
        body_content = self._serialize.body(action_rule_patch, 'PatchObject')

        # Construct and send request
        request = self._client.patch(url, query_parameters, header_parameters, body_content)
        response = self._client.send(request, stream=False, **operation_config)

        if response.status_code not in [200]:
            raise models.ErrorResponseException(self._deserialize, response)

        header_dict = {}
        deserialized = None
        if response.status_code == 200:
            deserialized = self._deserialize('ActionRule', response)
            header_dict = {
                'x-ms-request-id': 'str',
            }

        if raw:
            client_raw_response = ClientRawResponse(deserialized, response)
            client_raw_response.add_headers(header_dict)
            return client_raw_response

        return deserialized
    update.metadata = {'url': '/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AlertsManagement/actionRules/{actionRuleName}'}
