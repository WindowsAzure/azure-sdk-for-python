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

from msrest.service_client import SDKClient
from msrest import Serializer, Deserializer
from msrestazure import AzureConfiguration
from .version import VERSION
from .operations.policy_operations import PolicyOperations
from .operations.policy_snippets_operations import PolicySnippetsOperations
from .operations.regions_operations import RegionsOperations
from .operations.api_operations import ApiOperations
from .operations.api_revisions_operations import ApiRevisionsOperations
from .operations.api_release_operations import ApiReleaseOperations
from .operations.api_operation_operations import ApiOperationOperations
from .operations.api_operation_policy_operations import ApiOperationPolicyOperations
from .operations.api_product_operations import ApiProductOperations
from .operations.api_policy_operations import ApiPolicyOperations
from .operations.api_schema_operations import ApiSchemaOperations
from .operations.api_diagnostic_operations import ApiDiagnosticOperations
from .operations.api_issue_operations import ApiIssueOperations
from .operations.api_issue_comment_operations import ApiIssueCommentOperations
from .operations.api_issue_attachment_operations import ApiIssueAttachmentOperations
from .operations.authorization_server_operations import AuthorizationServerOperations
from .operations.backend_operations import BackendOperations
from .operations.certificate_operations import CertificateOperations
from .operations.api_management_operations import ApiManagementOperations
from .operations.api_management_service_operations import ApiManagementServiceOperations
from .operations.diagnostic_operations import DiagnosticOperations
from .operations.email_template_operations import EmailTemplateOperations
from .operations.group_operations import GroupOperations
from .operations.group_user_operations import GroupUserOperations
from .operations.identity_provider_operations import IdentityProviderOperations
from .operations.logger_operations import LoggerOperations
from .operations.notification_operations import NotificationOperations
from .operations.notification_recipient_user_operations import NotificationRecipientUserOperations
from .operations.notification_recipient_email_operations import NotificationRecipientEmailOperations
from .operations.network_status_operations import NetworkStatusOperations
from .operations.open_id_connect_provider_operations import OpenIdConnectProviderOperations
from .operations.sign_in_settings_operations import SignInSettingsOperations
from .operations.sign_up_settings_operations import SignUpSettingsOperations
from .operations.delegation_settings_operations import DelegationSettingsOperations
from .operations.product_operations import ProductOperations
from .operations.product_api_operations import ProductApiOperations
from .operations.product_group_operations import ProductGroupOperations
from .operations.product_subscriptions_operations import ProductSubscriptionsOperations
from .operations.product_policy_operations import ProductPolicyOperations
from .operations.property_operations import PropertyOperations
from .operations.quota_by_counter_keys_operations import QuotaByCounterKeysOperations
from .operations.quota_by_period_keys_operations import QuotaByPeriodKeysOperations
from .operations.reports_operations import ReportsOperations
from .operations.subscription_operations import SubscriptionOperations
from .operations.tag_resource_operations import TagResourceOperations
from .operations.tag_operations import TagOperations
from .operations.tag_description_operations import TagDescriptionOperations
from .operations.operation_operations import OperationOperations
from .operations.tenant_access_operations import TenantAccessOperations
from .operations.tenant_access_git_operations import TenantAccessGitOperations
from .operations.tenant_configuration_operations import TenantConfigurationOperations
from .operations.user_operations import UserOperations
from .operations.user_group_operations import UserGroupOperations
from .operations.user_subscription_operations import UserSubscriptionOperations
from .operations.user_identities_operations import UserIdentitiesOperations
from .operations.api_version_set_operations import ApiVersionSetOperations
from .operations.api_export_operations import ApiExportOperations
from . import models


class ApiManagementClientConfiguration(AzureConfiguration):
    """Configuration for ApiManagementClient
    Note that all parameters used to create this instance are saved as instance
    attributes.

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        if credentials is None:
            raise ValueError("Parameter 'credentials' must not be None.")
        if subscription_id is None:
            raise ValueError("Parameter 'subscription_id' must not be None.")
        if not base_url:
            base_url = 'https://management.azure.com'

        super(ApiManagementClientConfiguration, self).__init__(base_url)

        self.add_user_agent('azure-mgmt-apimanagement/{}'.format(VERSION))
        self.add_user_agent('Azure-SDK-For-Python')

        self.credentials = credentials
        self.subscription_id = subscription_id


class ApiManagementClient(SDKClient):
    """ApiManagement Client

    :ivar config: Configuration for client.
    :vartype config: ApiManagementClientConfiguration

    :ivar policy: Policy operations
    :vartype policy: azure.mgmt.apimanagement.operations.PolicyOperations
    :ivar policy_snippets: PolicySnippets operations
    :vartype policy_snippets: azure.mgmt.apimanagement.operations.PolicySnippetsOperations
    :ivar regions: Regions operations
    :vartype regions: azure.mgmt.apimanagement.operations.RegionsOperations
    :ivar api: Api operations
    :vartype api: azure.mgmt.apimanagement.operations.ApiOperations
    :ivar api_revisions: ApiRevisions operations
    :vartype api_revisions: azure.mgmt.apimanagement.operations.ApiRevisionsOperations
    :ivar api_release: ApiRelease operations
    :vartype api_release: azure.mgmt.apimanagement.operations.ApiReleaseOperations
    :ivar api_operation: ApiOperation operations
    :vartype api_operation: azure.mgmt.apimanagement.operations.ApiOperationOperations
    :ivar api_operation_policy: ApiOperationPolicy operations
    :vartype api_operation_policy: azure.mgmt.apimanagement.operations.ApiOperationPolicyOperations
    :ivar api_product: ApiProduct operations
    :vartype api_product: azure.mgmt.apimanagement.operations.ApiProductOperations
    :ivar api_policy: ApiPolicy operations
    :vartype api_policy: azure.mgmt.apimanagement.operations.ApiPolicyOperations
    :ivar api_schema: ApiSchema operations
    :vartype api_schema: azure.mgmt.apimanagement.operations.ApiSchemaOperations
    :ivar api_diagnostic: ApiDiagnostic operations
    :vartype api_diagnostic: azure.mgmt.apimanagement.operations.ApiDiagnosticOperations
    :ivar api_issue: ApiIssue operations
    :vartype api_issue: azure.mgmt.apimanagement.operations.ApiIssueOperations
    :ivar api_issue_comment: ApiIssueComment operations
    :vartype api_issue_comment: azure.mgmt.apimanagement.operations.ApiIssueCommentOperations
    :ivar api_issue_attachment: ApiIssueAttachment operations
    :vartype api_issue_attachment: azure.mgmt.apimanagement.operations.ApiIssueAttachmentOperations
    :ivar authorization_server: AuthorizationServer operations
    :vartype authorization_server: azure.mgmt.apimanagement.operations.AuthorizationServerOperations
    :ivar backend: Backend operations
    :vartype backend: azure.mgmt.apimanagement.operations.BackendOperations
    :ivar certificate: Certificate operations
    :vartype certificate: azure.mgmt.apimanagement.operations.CertificateOperations
    :ivar api_management_operations: ApiManagementOperations operations
    :vartype api_management_operations: azure.mgmt.apimanagement.operations.ApiManagementOperations
    :ivar api_management_service: ApiManagementService operations
    :vartype api_management_service: azure.mgmt.apimanagement.operations.ApiManagementServiceOperations
    :ivar diagnostic: Diagnostic operations
    :vartype diagnostic: azure.mgmt.apimanagement.operations.DiagnosticOperations
    :ivar email_template: EmailTemplate operations
    :vartype email_template: azure.mgmt.apimanagement.operations.EmailTemplateOperations
    :ivar group: Group operations
    :vartype group: azure.mgmt.apimanagement.operations.GroupOperations
    :ivar group_user: GroupUser operations
    :vartype group_user: azure.mgmt.apimanagement.operations.GroupUserOperations
    :ivar identity_provider: IdentityProvider operations
    :vartype identity_provider: azure.mgmt.apimanagement.operations.IdentityProviderOperations
    :ivar logger: Logger operations
    :vartype logger: azure.mgmt.apimanagement.operations.LoggerOperations
    :ivar notification: Notification operations
    :vartype notification: azure.mgmt.apimanagement.operations.NotificationOperations
    :ivar notification_recipient_user: NotificationRecipientUser operations
    :vartype notification_recipient_user: azure.mgmt.apimanagement.operations.NotificationRecipientUserOperations
    :ivar notification_recipient_email: NotificationRecipientEmail operations
    :vartype notification_recipient_email: azure.mgmt.apimanagement.operations.NotificationRecipientEmailOperations
    :ivar network_status: NetworkStatus operations
    :vartype network_status: azure.mgmt.apimanagement.operations.NetworkStatusOperations
    :ivar open_id_connect_provider: OpenIdConnectProvider operations
    :vartype open_id_connect_provider: azure.mgmt.apimanagement.operations.OpenIdConnectProviderOperations
    :ivar sign_in_settings: SignInSettings operations
    :vartype sign_in_settings: azure.mgmt.apimanagement.operations.SignInSettingsOperations
    :ivar sign_up_settings: SignUpSettings operations
    :vartype sign_up_settings: azure.mgmt.apimanagement.operations.SignUpSettingsOperations
    :ivar delegation_settings: DelegationSettings operations
    :vartype delegation_settings: azure.mgmt.apimanagement.operations.DelegationSettingsOperations
    :ivar product: Product operations
    :vartype product: azure.mgmt.apimanagement.operations.ProductOperations
    :ivar product_api: ProductApi operations
    :vartype product_api: azure.mgmt.apimanagement.operations.ProductApiOperations
    :ivar product_group: ProductGroup operations
    :vartype product_group: azure.mgmt.apimanagement.operations.ProductGroupOperations
    :ivar product_subscriptions: ProductSubscriptions operations
    :vartype product_subscriptions: azure.mgmt.apimanagement.operations.ProductSubscriptionsOperations
    :ivar product_policy: ProductPolicy operations
    :vartype product_policy: azure.mgmt.apimanagement.operations.ProductPolicyOperations
    :ivar property: Property operations
    :vartype property: azure.mgmt.apimanagement.operations.PropertyOperations
    :ivar quota_by_counter_keys: QuotaByCounterKeys operations
    :vartype quota_by_counter_keys: azure.mgmt.apimanagement.operations.QuotaByCounterKeysOperations
    :ivar quota_by_period_keys: QuotaByPeriodKeys operations
    :vartype quota_by_period_keys: azure.mgmt.apimanagement.operations.QuotaByPeriodKeysOperations
    :ivar reports: Reports operations
    :vartype reports: azure.mgmt.apimanagement.operations.ReportsOperations
    :ivar subscription: Subscription operations
    :vartype subscription: azure.mgmt.apimanagement.operations.SubscriptionOperations
    :ivar tag_resource: TagResource operations
    :vartype tag_resource: azure.mgmt.apimanagement.operations.TagResourceOperations
    :ivar tag: Tag operations
    :vartype tag: azure.mgmt.apimanagement.operations.TagOperations
    :ivar tag_description: TagDescription operations
    :vartype tag_description: azure.mgmt.apimanagement.operations.TagDescriptionOperations
    :ivar operation: Operation operations
    :vartype operation: azure.mgmt.apimanagement.operations.OperationOperations
    :ivar tenant_access: TenantAccess operations
    :vartype tenant_access: azure.mgmt.apimanagement.operations.TenantAccessOperations
    :ivar tenant_access_git: TenantAccessGit operations
    :vartype tenant_access_git: azure.mgmt.apimanagement.operations.TenantAccessGitOperations
    :ivar tenant_configuration: TenantConfiguration operations
    :vartype tenant_configuration: azure.mgmt.apimanagement.operations.TenantConfigurationOperations
    :ivar user: User operations
    :vartype user: azure.mgmt.apimanagement.operations.UserOperations
    :ivar user_group: UserGroup operations
    :vartype user_group: azure.mgmt.apimanagement.operations.UserGroupOperations
    :ivar user_subscription: UserSubscription operations
    :vartype user_subscription: azure.mgmt.apimanagement.operations.UserSubscriptionOperations
    :ivar user_identities: UserIdentities operations
    :vartype user_identities: azure.mgmt.apimanagement.operations.UserIdentitiesOperations
    :ivar api_version_set: ApiVersionSet operations
    :vartype api_version_set: azure.mgmt.apimanagement.operations.ApiVersionSetOperations
    :ivar api_export: ApiExport operations
    :vartype api_export: azure.mgmt.apimanagement.operations.ApiExportOperations

    :param credentials: Credentials needed for the client to connect to Azure.
    :type credentials: :mod:`A msrestazure Credentials
     object<msrestazure.azure_active_directory>`
    :param subscription_id: Subscription credentials which uniquely identify
     Microsoft Azure subscription. The subscription ID forms part of the URI
     for every service call.
    :type subscription_id: str
    :param str base_url: Service URL
    """

    def __init__(
            self, credentials, subscription_id, base_url=None):

        self.config = ApiManagementClientConfiguration(credentials, subscription_id, base_url)
        super(ApiManagementClient, self).__init__(self.config.credentials, self.config)

        client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
        self.api_version = '2018-06-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.policy = PolicyOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.policy_snippets = PolicySnippetsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.regions = RegionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api = ApiOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_revisions = ApiRevisionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_release = ApiReleaseOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_operation = ApiOperationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_operation_policy = ApiOperationPolicyOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_product = ApiProductOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_policy = ApiPolicyOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_schema = ApiSchemaOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_diagnostic = ApiDiagnosticOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_issue = ApiIssueOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_issue_comment = ApiIssueCommentOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_issue_attachment = ApiIssueAttachmentOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.authorization_server = AuthorizationServerOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.backend = BackendOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.certificate = CertificateOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_management_operations = ApiManagementOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_management_service = ApiManagementServiceOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.diagnostic = DiagnosticOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.email_template = EmailTemplateOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.group = GroupOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.group_user = GroupUserOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.identity_provider = IdentityProviderOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.logger = LoggerOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.notification = NotificationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.notification_recipient_user = NotificationRecipientUserOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.notification_recipient_email = NotificationRecipientEmailOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_status = NetworkStatusOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.open_id_connect_provider = OpenIdConnectProviderOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.sign_in_settings = SignInSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.sign_up_settings = SignUpSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.delegation_settings = DelegationSettingsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.product = ProductOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.product_api = ProductApiOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.product_group = ProductGroupOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.product_subscriptions = ProductSubscriptionsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.product_policy = ProductPolicyOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.property = PropertyOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.quota_by_counter_keys = QuotaByCounterKeysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.quota_by_period_keys = QuotaByPeriodKeysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.reports = ReportsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.subscription = SubscriptionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tag_resource = TagResourceOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tag = TagOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tag_description = TagDescriptionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operation = OperationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tenant_access = TenantAccessOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tenant_access_git = TenantAccessGitOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tenant_configuration = TenantConfigurationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.user = UserOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.user_group = UserGroupOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.user_subscription = UserSubscriptionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.user_identities = UserIdentitiesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_version_set = ApiVersionSetOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_export = ApiExportOperations(
            self._client, self.config, self._serialize, self._deserialize)
