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

from ._configuration import ApiManagementClientConfiguration
from .operations import ApiOperations
from .operations import ApiRevisionOperations
from .operations import ApiReleaseOperations
from .operations import ApiOperationOperations
from .operations import ApiOperationPolicyOperations
from .operations import TagOperations
from .operations import ApiProductOperations
from .operations import ApiPolicyOperations
from .operations import ApiSchemaOperations
from .operations import ApiDiagnosticOperations
from .operations import ApiIssueOperations
from .operations import ApiIssueCommentOperations
from .operations import ApiIssueAttachmentOperations
from .operations import ApiTagDescriptionOperations
from .operations import OperationOperations
from .operations import ApiVersionSetOperations
from .operations import AuthorizationServerOperations
from .operations import BackendOperations
from .operations import CacheOperations
from .operations import CertificateOperations
from .operations import ContentTypeOperations
from .operations import ContentTypeContentItemOperations
from .operations import DeletedServicesOperations
from .operations import ApiManagementOperations
from .operations import ApiManagementServiceSkusOperations
from .operations import ApiManagementServiceOperations
from .operations import DiagnosticOperations
from .operations import EmailTemplateOperations
from .operations import GatewayOperations
from .operations import GatewayHostnameConfigurationOperations
from .operations import GatewayApiOperations
from .operations import GroupOperations
from .operations import GroupUserOperations
from .operations import IdentityProviderOperations
from .operations import IssueOperations
from .operations import LoggerOperations
from .operations import NamedValueOperations
from .operations import NetworkStatusOperations
from .operations import NotificationOperations
from .operations import NotificationRecipientUserOperations
from .operations import NotificationRecipientEmailOperations
from .operations import OpenIdConnectProviderOperations
from .operations import PolicyOperations
from .operations import PolicyDescriptionOperations
from .operations import SignInSettingsOperations
from .operations import SignUpSettingsOperations
from .operations import DelegationSettingsOperations
from .operations import ProductOperations
from .operations import ProductApiOperations
from .operations import ProductGroupOperations
from .operations import ProductSubscriptionsOperations
from .operations import ProductPolicyOperations
from .operations import QuotaByCounterKeysOperations
from .operations import QuotaByPeriodKeysOperations
from .operations import RegionOperations
from .operations import ReportsOperations
from .operations import SubscriptionOperations
from .operations import TagResourceOperations
from .operations import TenantAccessOperations
from .operations import TenantAccessGitOperations
from .operations import TenantConfigurationOperations
from .operations import UserOperations
from .operations import UserGroupOperations
from .operations import UserSubscriptionOperations
from .operations import UserIdentitiesOperations
from .operations import UserConfirmationPasswordOperations
from .operations import ApiExportOperations
from . import models


class ApiManagementClient(SDKClient):
    """ApiManagement Client

    :ivar config: Configuration for client.
    :vartype config: ApiManagementClientConfiguration

    :ivar api: Api operations
    :vartype api: azure.mgmt.apimanagement.operations.ApiOperations
    :ivar api_revision: ApiRevision operations
    :vartype api_revision: azure.mgmt.apimanagement.operations.ApiRevisionOperations
    :ivar api_release: ApiRelease operations
    :vartype api_release: azure.mgmt.apimanagement.operations.ApiReleaseOperations
    :ivar api_operation: ApiOperation operations
    :vartype api_operation: azure.mgmt.apimanagement.operations.ApiOperationOperations
    :ivar api_operation_policy: ApiOperationPolicy operations
    :vartype api_operation_policy: azure.mgmt.apimanagement.operations.ApiOperationPolicyOperations
    :ivar tag: Tag operations
    :vartype tag: azure.mgmt.apimanagement.operations.TagOperations
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
    :ivar api_tag_description: ApiTagDescription operations
    :vartype api_tag_description: azure.mgmt.apimanagement.operations.ApiTagDescriptionOperations
    :ivar operation: Operation operations
    :vartype operation: azure.mgmt.apimanagement.operations.OperationOperations
    :ivar api_version_set: ApiVersionSet operations
    :vartype api_version_set: azure.mgmt.apimanagement.operations.ApiVersionSetOperations
    :ivar authorization_server: AuthorizationServer operations
    :vartype authorization_server: azure.mgmt.apimanagement.operations.AuthorizationServerOperations
    :ivar backend: Backend operations
    :vartype backend: azure.mgmt.apimanagement.operations.BackendOperations
    :ivar cache: Cache operations
    :vartype cache: azure.mgmt.apimanagement.operations.CacheOperations
    :ivar certificate: Certificate operations
    :vartype certificate: azure.mgmt.apimanagement.operations.CertificateOperations
    :ivar content_type: ContentType operations
    :vartype content_type: azure.mgmt.apimanagement.operations.ContentTypeOperations
    :ivar content_type_content_item: ContentTypeContentItem operations
    :vartype content_type_content_item: azure.mgmt.apimanagement.operations.ContentTypeContentItemOperations
    :ivar deleted_services: DeletedServices operations
    :vartype deleted_services: azure.mgmt.apimanagement.operations.DeletedServicesOperations
    :ivar api_management_operations: ApiManagementOperations operations
    :vartype api_management_operations: azure.mgmt.apimanagement.operations.ApiManagementOperations
    :ivar api_management_service_skus: ApiManagementServiceSkus operations
    :vartype api_management_service_skus: azure.mgmt.apimanagement.operations.ApiManagementServiceSkusOperations
    :ivar api_management_service: ApiManagementService operations
    :vartype api_management_service: azure.mgmt.apimanagement.operations.ApiManagementServiceOperations
    :ivar diagnostic: Diagnostic operations
    :vartype diagnostic: azure.mgmt.apimanagement.operations.DiagnosticOperations
    :ivar email_template: EmailTemplate operations
    :vartype email_template: azure.mgmt.apimanagement.operations.EmailTemplateOperations
    :ivar gateway: Gateway operations
    :vartype gateway: azure.mgmt.apimanagement.operations.GatewayOperations
    :ivar gateway_hostname_configuration: GatewayHostnameConfiguration operations
    :vartype gateway_hostname_configuration: azure.mgmt.apimanagement.operations.GatewayHostnameConfigurationOperations
    :ivar gateway_api: GatewayApi operations
    :vartype gateway_api: azure.mgmt.apimanagement.operations.GatewayApiOperations
    :ivar group: Group operations
    :vartype group: azure.mgmt.apimanagement.operations.GroupOperations
    :ivar group_user: GroupUser operations
    :vartype group_user: azure.mgmt.apimanagement.operations.GroupUserOperations
    :ivar identity_provider: IdentityProvider operations
    :vartype identity_provider: azure.mgmt.apimanagement.operations.IdentityProviderOperations
    :ivar issue: Issue operations
    :vartype issue: azure.mgmt.apimanagement.operations.IssueOperations
    :ivar logger: Logger operations
    :vartype logger: azure.mgmt.apimanagement.operations.LoggerOperations
    :ivar named_value: NamedValue operations
    :vartype named_value: azure.mgmt.apimanagement.operations.NamedValueOperations
    :ivar network_status: NetworkStatus operations
    :vartype network_status: azure.mgmt.apimanagement.operations.NetworkStatusOperations
    :ivar notification: Notification operations
    :vartype notification: azure.mgmt.apimanagement.operations.NotificationOperations
    :ivar notification_recipient_user: NotificationRecipientUser operations
    :vartype notification_recipient_user: azure.mgmt.apimanagement.operations.NotificationRecipientUserOperations
    :ivar notification_recipient_email: NotificationRecipientEmail operations
    :vartype notification_recipient_email: azure.mgmt.apimanagement.operations.NotificationRecipientEmailOperations
    :ivar open_id_connect_provider: OpenIdConnectProvider operations
    :vartype open_id_connect_provider: azure.mgmt.apimanagement.operations.OpenIdConnectProviderOperations
    :ivar policy: Policy operations
    :vartype policy: azure.mgmt.apimanagement.operations.PolicyOperations
    :ivar policy_description: PolicyDescription operations
    :vartype policy_description: azure.mgmt.apimanagement.operations.PolicyDescriptionOperations
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
    :ivar quota_by_counter_keys: QuotaByCounterKeys operations
    :vartype quota_by_counter_keys: azure.mgmt.apimanagement.operations.QuotaByCounterKeysOperations
    :ivar quota_by_period_keys: QuotaByPeriodKeys operations
    :vartype quota_by_period_keys: azure.mgmt.apimanagement.operations.QuotaByPeriodKeysOperations
    :ivar region: Region operations
    :vartype region: azure.mgmt.apimanagement.operations.RegionOperations
    :ivar reports: Reports operations
    :vartype reports: azure.mgmt.apimanagement.operations.ReportsOperations
    :ivar subscription: Subscription operations
    :vartype subscription: azure.mgmt.apimanagement.operations.SubscriptionOperations
    :ivar tag_resource: TagResource operations
    :vartype tag_resource: azure.mgmt.apimanagement.operations.TagResourceOperations
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
    :ivar user_confirmation_password: UserConfirmationPassword operations
    :vartype user_confirmation_password: azure.mgmt.apimanagement.operations.UserConfirmationPasswordOperations
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
        self.api_version = '2020-06-01-preview'
        self._serialize = Serializer(client_models)
        self._deserialize = Deserializer(client_models)

        self.api = ApiOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_revision = ApiRevisionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_release = ApiReleaseOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_operation = ApiOperationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_operation_policy = ApiOperationPolicyOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tag = TagOperations(
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
        self.api_tag_description = ApiTagDescriptionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.operation = OperationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_version_set = ApiVersionSetOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.authorization_server = AuthorizationServerOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.backend = BackendOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.cache = CacheOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.certificate = CertificateOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.content_type = ContentTypeOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.content_type_content_item = ContentTypeContentItemOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.deleted_services = DeletedServicesOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_management_operations = ApiManagementOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_management_service_skus = ApiManagementServiceSkusOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_management_service = ApiManagementServiceOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.diagnostic = DiagnosticOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.email_template = EmailTemplateOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.gateway = GatewayOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.gateway_hostname_configuration = GatewayHostnameConfigurationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.gateway_api = GatewayApiOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.group = GroupOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.group_user = GroupUserOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.identity_provider = IdentityProviderOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.issue = IssueOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.logger = LoggerOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.named_value = NamedValueOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.network_status = NetworkStatusOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.notification = NotificationOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.notification_recipient_user = NotificationRecipientUserOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.notification_recipient_email = NotificationRecipientEmailOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.open_id_connect_provider = OpenIdConnectProviderOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.policy = PolicyOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.policy_description = PolicyDescriptionOperations(
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
        self.quota_by_counter_keys = QuotaByCounterKeysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.quota_by_period_keys = QuotaByPeriodKeysOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.region = RegionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.reports = ReportsOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.subscription = SubscriptionOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.tag_resource = TagResourceOperations(
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
        self.user_confirmation_password = UserConfirmationPasswordOperations(
            self._client, self.config, self._serialize, self._deserialize)
        self.api_export = ApiExportOperations(
            self._client, self.config, self._serialize, self._deserialize)
