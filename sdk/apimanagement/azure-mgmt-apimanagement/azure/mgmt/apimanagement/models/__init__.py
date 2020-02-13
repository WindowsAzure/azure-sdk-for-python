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

try:
    from ._models_py3 import AccessInformationContract
    from ._models_py3 import AccessInformationUpdateParameters
    from ._models_py3 import AdditionalLocation
    from ._models_py3 import ApiContract
    from ._models_py3 import ApiContractProperties
    from ._models_py3 import ApiCreateOrUpdateParameter
    from ._models_py3 import ApiCreateOrUpdatePropertiesWsdlSelector
    from ._models_py3 import ApiEntityBaseContract
    from ._models_py3 import ApiExportResult
    from ._models_py3 import ApiExportResultValue
    from ._models_py3 import ApiManagementServiceApplyNetworkConfigurationParameters
    from ._models_py3 import ApiManagementServiceBackupRestoreParameters
    from ._models_py3 import ApiManagementServiceBaseProperties
    from ._models_py3 import ApiManagementServiceCheckNameAvailabilityParameters
    from ._models_py3 import ApiManagementServiceGetSsoTokenResult
    from ._models_py3 import ApiManagementServiceIdentity
    from ._models_py3 import ApiManagementServiceIdentityUserAssignedIdentitiesValue
    from ._models_py3 import ApiManagementServiceNameAvailabilityResult
    from ._models_py3 import ApiManagementServiceResource
    from ._models_py3 import ApiManagementServiceSkuProperties
    from ._models_py3 import ApiManagementServiceUpdateParameters
    from ._models_py3 import ApimResource
    from ._models_py3 import ApiReleaseContract
    from ._models_py3 import ApiRevisionContract
    from ._models_py3 import ApiRevisionInfoContract
    from ._models_py3 import ApiTagResourceContractProperties
    from ._models_py3 import ApiUpdateContract
    from ._models_py3 import ApiVersionConstraint
    from ._models_py3 import ApiVersionSetContract
    from ._models_py3 import ApiVersionSetContractDetails
    from ._models_py3 import ApiVersionSetEntityBase
    from ._models_py3 import ApiVersionSetUpdateParameters
    from ._models_py3 import AuthenticationSettingsContract
    from ._models_py3 import AuthorizationServerContract
    from ._models_py3 import AuthorizationServerContractBaseProperties
    from ._models_py3 import AuthorizationServerUpdateContract
    from ._models_py3 import BackendAuthorizationHeaderCredentials
    from ._models_py3 import BackendBaseParameters
    from ._models_py3 import BackendContract
    from ._models_py3 import BackendCredentialsContract
    from ._models_py3 import BackendProperties
    from ._models_py3 import BackendProxyContract
    from ._models_py3 import BackendReconnectContract
    from ._models_py3 import BackendServiceFabricClusterProperties
    from ._models_py3 import BackendTlsProperties
    from ._models_py3 import BackendUpdateParameters
    from ._models_py3 import BodyDiagnosticSettings
    from ._models_py3 import CacheContract
    from ._models_py3 import CacheUpdateParameters
    from ._models_py3 import CertificateConfiguration
    from ._models_py3 import CertificateContract
    from ._models_py3 import CertificateCreateOrUpdateParameters
    from ._models_py3 import CertificateInformation
    from ._models_py3 import ClientSecretContract
    from ._models_py3 import ConnectivityStatusContract
    from ._models_py3 import DeployConfigurationParameters
    from ._models_py3 import DiagnosticContract
    from ._models_py3 import EmailTemplateContract
    from ._models_py3 import EmailTemplateParametersContractProperties
    from ._models_py3 import EmailTemplateUpdateParameters
    from ._models_py3 import ErrorFieldContract
    from ._models_py3 import ErrorResponse, ErrorResponseException
    from ._models_py3 import ErrorResponseBody
    from ._models_py3 import GenerateSsoUrlResult
    from ._models_py3 import GroupContract
    from ._models_py3 import GroupContractProperties
    from ._models_py3 import GroupCreateParameters
    from ._models_py3 import GroupUpdateParameters
    from ._models_py3 import HostnameConfiguration
    from ._models_py3 import HttpMessageDiagnostic
    from ._models_py3 import IdentityProviderBaseParameters
    from ._models_py3 import IdentityProviderContract
    from ._models_py3 import IdentityProviderCreateContract
    from ._models_py3 import IdentityProviderUpdateParameters
    from ._models_py3 import IssueAttachmentContract
    from ._models_py3 import IssueCommentContract
    from ._models_py3 import IssueContract
    from ._models_py3 import IssueContractBaseProperties
    from ._models_py3 import IssueUpdateContract
    from ._models_py3 import LoggerContract
    from ._models_py3 import LoggerUpdateContract
    from ._models_py3 import NamedValueContract
    from ._models_py3 import NamedValueCreateContract
    from ._models_py3 import NamedValueEntityBaseParameters
    from ._models_py3 import NamedValueUpdateParameters
    from ._models_py3 import NetworkStatusContract
    from ._models_py3 import NetworkStatusContractByLocation
    from ._models_py3 import NotificationContract
    from ._models_py3 import OAuth2AuthenticationSettingsContract
    from ._models_py3 import OpenIdAuthenticationSettingsContract
    from ._models_py3 import OpenidConnectProviderContract
    from ._models_py3 import OpenidConnectProviderCreateContract
    from ._models_py3 import OpenidConnectProviderUpdateContract
    from ._models_py3 import Operation
    from ._models_py3 import OperationContract
    from ._models_py3 import OperationDisplay
    from ._models_py3 import OperationEntityBaseContract
    from ._models_py3 import OperationResultContract
    from ._models_py3 import OperationResultLogItemContract
    from ._models_py3 import OperationTagResourceContractProperties
    from ._models_py3 import OperationUpdateContract
    from ._models_py3 import ParameterContract
    from ._models_py3 import PipelineDiagnosticSettings
    from ._models_py3 import PolicyCollection
    from ._models_py3 import PolicyContract
    from ._models_py3 import PolicyDescriptionCollection
    from ._models_py3 import PolicyDescriptionContract
    from ._models_py3 import PortalDelegationSettings
    from ._models_py3 import PortalSettingValidationKeyContract
    from ._models_py3 import PortalSigninSettings
    from ._models_py3 import PortalSignupSettings
    from ._models_py3 import ProductContract
    from ._models_py3 import ProductEntityBaseParameters
    from ._models_py3 import ProductTagResourceContractProperties
    from ._models_py3 import ProductUpdateParameters
    from ._models_py3 import PropertyValueContract
    from ._models_py3 import QuotaCounterCollection
    from ._models_py3 import QuotaCounterContract
    from ._models_py3 import QuotaCounterValueContract
    from ._models_py3 import QuotaCounterValueContractProperties
    from ._models_py3 import RecipientEmailCollection
    from ._models_py3 import RecipientEmailContract
    from ._models_py3 import RecipientsContractProperties
    from ._models_py3 import RecipientUserCollection
    from ._models_py3 import RecipientUserContract
    from ._models_py3 import RegionContract
    from ._models_py3 import RegistrationDelegationSettingsProperties
    from ._models_py3 import ReportRecordContract
    from ._models_py3 import RepresentationContract
    from ._models_py3 import RequestContract
    from ._models_py3 import RequestReportRecordContract
    from ._models_py3 import Resource
    from ._models_py3 import ResourceSku
    from ._models_py3 import ResourceSkuCapacity
    from ._models_py3 import ResourceSkuResult
    from ._models_py3 import ResponseContract
    from ._models_py3 import SamplingSettings
    from ._models_py3 import SaveConfigurationParameter
    from ._models_py3 import SchemaContract
    from ._models_py3 import SubscriptionContract
    from ._models_py3 import SubscriptionCreateParameters
    from ._models_py3 import SubscriptionKeyParameterNamesContract
    from ._models_py3 import SubscriptionKeysContract
    from ._models_py3 import SubscriptionsDelegationSettingsProperties
    from ._models_py3 import SubscriptionUpdateParameters
    from ._models_py3 import TagContract
    from ._models_py3 import TagCreateUpdateParameters
    from ._models_py3 import TagDescriptionContract
    from ._models_py3 import TagDescriptionCreateParameters
    from ._models_py3 import TagResourceContract
    from ._models_py3 import TagTagResourceContractProperties
    from ._models_py3 import TenantConfigurationSyncStateContract
    from ._models_py3 import TermsOfServiceProperties
    from ._models_py3 import TokenBodyParameterContract
    from ._models_py3 import UserContract
    from ._models_py3 import UserCreateParameters
    from ._models_py3 import UserEntityBaseParameters
    from ._models_py3 import UserIdentityContract
    from ._models_py3 import UserTokenParameters
    from ._models_py3 import UserTokenResult
    from ._models_py3 import UserUpdateParameters
    from ._models_py3 import VirtualNetworkConfiguration
    from ._models_py3 import X509CertificateName
except (SyntaxError, ImportError):
    from ._models import AccessInformationContract
    from ._models import AccessInformationUpdateParameters
    from ._models import AdditionalLocation
    from ._models import ApiContract
    from ._models import ApiContractProperties
    from ._models import ApiCreateOrUpdateParameter
    from ._models import ApiCreateOrUpdatePropertiesWsdlSelector
    from ._models import ApiEntityBaseContract
    from ._models import ApiExportResult
    from ._models import ApiExportResultValue
    from ._models import ApiManagementServiceApplyNetworkConfigurationParameters
    from ._models import ApiManagementServiceBackupRestoreParameters
    from ._models import ApiManagementServiceBaseProperties
    from ._models import ApiManagementServiceCheckNameAvailabilityParameters
    from ._models import ApiManagementServiceGetSsoTokenResult
    from ._models import ApiManagementServiceIdentity
    from ._models import ApiManagementServiceIdentityUserAssignedIdentitiesValue
    from ._models import ApiManagementServiceNameAvailabilityResult
    from ._models import ApiManagementServiceResource
    from ._models import ApiManagementServiceSkuProperties
    from ._models import ApiManagementServiceUpdateParameters
    from ._models import ApimResource
    from ._models import ApiReleaseContract
    from ._models import ApiRevisionContract
    from ._models import ApiRevisionInfoContract
    from ._models import ApiTagResourceContractProperties
    from ._models import ApiUpdateContract
    from ._models import ApiVersionConstraint
    from ._models import ApiVersionSetContract
    from ._models import ApiVersionSetContractDetails
    from ._models import ApiVersionSetEntityBase
    from ._models import ApiVersionSetUpdateParameters
    from ._models import AuthenticationSettingsContract
    from ._models import AuthorizationServerContract
    from ._models import AuthorizationServerContractBaseProperties
    from ._models import AuthorizationServerUpdateContract
    from ._models import BackendAuthorizationHeaderCredentials
    from ._models import BackendBaseParameters
    from ._models import BackendContract
    from ._models import BackendCredentialsContract
    from ._models import BackendProperties
    from ._models import BackendProxyContract
    from ._models import BackendReconnectContract
    from ._models import BackendServiceFabricClusterProperties
    from ._models import BackendTlsProperties
    from ._models import BackendUpdateParameters
    from ._models import BodyDiagnosticSettings
    from ._models import CacheContract
    from ._models import CacheUpdateParameters
    from ._models import CertificateConfiguration
    from ._models import CertificateContract
    from ._models import CertificateCreateOrUpdateParameters
    from ._models import CertificateInformation
    from ._models import ClientSecretContract
    from ._models import ConnectivityStatusContract
    from ._models import DeployConfigurationParameters
    from ._models import DiagnosticContract
    from ._models import EmailTemplateContract
    from ._models import EmailTemplateParametersContractProperties
    from ._models import EmailTemplateUpdateParameters
    from ._models import ErrorFieldContract
    from ._models import ErrorResponse, ErrorResponseException
    from ._models import ErrorResponseBody
    from ._models import GenerateSsoUrlResult
    from ._models import GroupContract
    from ._models import GroupContractProperties
    from ._models import GroupCreateParameters
    from ._models import GroupUpdateParameters
    from ._models import HostnameConfiguration
    from ._models import HttpMessageDiagnostic
    from ._models import IdentityProviderBaseParameters
    from ._models import IdentityProviderContract
    from ._models import IdentityProviderCreateContract
    from ._models import IdentityProviderUpdateParameters
    from ._models import IssueAttachmentContract
    from ._models import IssueCommentContract
    from ._models import IssueContract
    from ._models import IssueContractBaseProperties
    from ._models import IssueUpdateContract
    from ._models import LoggerContract
    from ._models import LoggerUpdateContract
    from ._models import NamedValueContract
    from ._models import NamedValueCreateContract
    from ._models import NamedValueEntityBaseParameters
    from ._models import NamedValueUpdateParameters
    from ._models import NetworkStatusContract
    from ._models import NetworkStatusContractByLocation
    from ._models import NotificationContract
    from ._models import OAuth2AuthenticationSettingsContract
    from ._models import OpenIdAuthenticationSettingsContract
    from ._models import OpenidConnectProviderContract
    from ._models import OpenidConnectProviderCreateContract
    from ._models import OpenidConnectProviderUpdateContract
    from ._models import Operation
    from ._models import OperationContract
    from ._models import OperationDisplay
    from ._models import OperationEntityBaseContract
    from ._models import OperationResultContract
    from ._models import OperationResultLogItemContract
    from ._models import OperationTagResourceContractProperties
    from ._models import OperationUpdateContract
    from ._models import ParameterContract
    from ._models import PipelineDiagnosticSettings
    from ._models import PolicyCollection
    from ._models import PolicyContract
    from ._models import PolicyDescriptionCollection
    from ._models import PolicyDescriptionContract
    from ._models import PortalDelegationSettings
    from ._models import PortalSettingValidationKeyContract
    from ._models import PortalSigninSettings
    from ._models import PortalSignupSettings
    from ._models import ProductContract
    from ._models import ProductEntityBaseParameters
    from ._models import ProductTagResourceContractProperties
    from ._models import ProductUpdateParameters
    from ._models import PropertyValueContract
    from ._models import QuotaCounterCollection
    from ._models import QuotaCounterContract
    from ._models import QuotaCounterValueContract
    from ._models import QuotaCounterValueContractProperties
    from ._models import RecipientEmailCollection
    from ._models import RecipientEmailContract
    from ._models import RecipientsContractProperties
    from ._models import RecipientUserCollection
    from ._models import RecipientUserContract
    from ._models import RegionContract
    from ._models import RegistrationDelegationSettingsProperties
    from ._models import ReportRecordContract
    from ._models import RepresentationContract
    from ._models import RequestContract
    from ._models import RequestReportRecordContract
    from ._models import Resource
    from ._models import ResourceSku
    from ._models import ResourceSkuCapacity
    from ._models import ResourceSkuResult
    from ._models import ResponseContract
    from ._models import SamplingSettings
    from ._models import SaveConfigurationParameter
    from ._models import SchemaContract
    from ._models import SubscriptionContract
    from ._models import SubscriptionCreateParameters
    from ._models import SubscriptionKeyParameterNamesContract
    from ._models import SubscriptionKeysContract
    from ._models import SubscriptionsDelegationSettingsProperties
    from ._models import SubscriptionUpdateParameters
    from ._models import TagContract
    from ._models import TagCreateUpdateParameters
    from ._models import TagDescriptionContract
    from ._models import TagDescriptionCreateParameters
    from ._models import TagResourceContract
    from ._models import TagTagResourceContractProperties
    from ._models import TenantConfigurationSyncStateContract
    from ._models import TermsOfServiceProperties
    from ._models import TokenBodyParameterContract
    from ._models import UserContract
    from ._models import UserCreateParameters
    from ._models import UserEntityBaseParameters
    from ._models import UserIdentityContract
    from ._models import UserTokenParameters
    from ._models import UserTokenResult
    from ._models import UserUpdateParameters
    from ._models import VirtualNetworkConfiguration
    from ._models import X509CertificateName
from ._paged_models import ApiContractPaged
from ._paged_models import ApiManagementServiceResourcePaged
from ._paged_models import ApiReleaseContractPaged
from ._paged_models import ApiRevisionContractPaged
from ._paged_models import ApiVersionSetContractPaged
from ._paged_models import AuthorizationServerContractPaged
from ._paged_models import BackendContractPaged
from ._paged_models import CacheContractPaged
from ._paged_models import CertificateContractPaged
from ._paged_models import DiagnosticContractPaged
from ._paged_models import EmailTemplateContractPaged
from ._paged_models import GroupContractPaged
from ._paged_models import IdentityProviderContractPaged
from ._paged_models import IssueAttachmentContractPaged
from ._paged_models import IssueCommentContractPaged
from ._paged_models import IssueContractPaged
from ._paged_models import LoggerContractPaged
from ._paged_models import NamedValueContractPaged
from ._paged_models import NotificationContractPaged
from ._paged_models import OpenidConnectProviderContractPaged
from ._paged_models import OperationContractPaged
from ._paged_models import OperationPaged
from ._paged_models import ProductContractPaged
from ._paged_models import RegionContractPaged
from ._paged_models import ReportRecordContractPaged
from ._paged_models import RequestReportRecordContractPaged
from ._paged_models import ResourceSkuResultPaged
from ._paged_models import SchemaContractPaged
from ._paged_models import SubscriptionContractPaged
from ._paged_models import TagContractPaged
from ._paged_models import TagDescriptionContractPaged
from ._paged_models import TagResourceContractPaged
from ._paged_models import UserContractPaged
from ._paged_models import UserIdentityContractPaged
from ._api_management_client_enums import (
    ExportResultFormat,
    ProductState,
    BearerTokenSendingMethods,
    Protocol,
    ContentFormat,
    SoapApiType,
    ApiType,
    State,
    SamplingType,
    AlwaysLog,
    HttpCorrelationProtocol,
    Verbosity,
    PolicyContentFormat,
    VersioningScheme,
    GrantType,
    AuthorizationMethod,
    ClientAuthenticationMethod,
    BearerTokenSendingMethod,
    BackendProtocol,
    SkuType,
    ResourceSkuCapacityScaleType,
    HostnameType,
    VirtualNetworkType,
    ApimIdentityType,
    NameAvailabilityReason,
    Confirmation,
    UserState,
    GroupType,
    IdentityProviderType,
    LoggerType,
    ConnectivityStatusType,
    SubscriptionState,
    AsyncOperationStatus,
    KeyType,
    NotificationName,
    PolicyExportFormat,
    TemplateName,
    PolicyScopeContract,
    ExportFormat,
)

__all__ = [
    'AccessInformationContract',
    'AccessInformationUpdateParameters',
    'AdditionalLocation',
    'ApiContract',
    'ApiContractProperties',
    'ApiCreateOrUpdateParameter',
    'ApiCreateOrUpdatePropertiesWsdlSelector',
    'ApiEntityBaseContract',
    'ApiExportResult',
    'ApiExportResultValue',
    'ApiManagementServiceApplyNetworkConfigurationParameters',
    'ApiManagementServiceBackupRestoreParameters',
    'ApiManagementServiceBaseProperties',
    'ApiManagementServiceCheckNameAvailabilityParameters',
    'ApiManagementServiceGetSsoTokenResult',
    'ApiManagementServiceIdentity',
    'ApiManagementServiceIdentityUserAssignedIdentitiesValue',
    'ApiManagementServiceNameAvailabilityResult',
    'ApiManagementServiceResource',
    'ApiManagementServiceSkuProperties',
    'ApiManagementServiceUpdateParameters',
    'ApimResource',
    'ApiReleaseContract',
    'ApiRevisionContract',
    'ApiRevisionInfoContract',
    'ApiTagResourceContractProperties',
    'ApiUpdateContract',
    'ApiVersionConstraint',
    'ApiVersionSetContract',
    'ApiVersionSetContractDetails',
    'ApiVersionSetEntityBase',
    'ApiVersionSetUpdateParameters',
    'AuthenticationSettingsContract',
    'AuthorizationServerContract',
    'AuthorizationServerContractBaseProperties',
    'AuthorizationServerUpdateContract',
    'BackendAuthorizationHeaderCredentials',
    'BackendBaseParameters',
    'BackendContract',
    'BackendCredentialsContract',
    'BackendProperties',
    'BackendProxyContract',
    'BackendReconnectContract',
    'BackendServiceFabricClusterProperties',
    'BackendTlsProperties',
    'BackendUpdateParameters',
    'BodyDiagnosticSettings',
    'CacheContract',
    'CacheUpdateParameters',
    'CertificateConfiguration',
    'CertificateContract',
    'CertificateCreateOrUpdateParameters',
    'CertificateInformation',
    'ClientSecretContract',
    'ConnectivityStatusContract',
    'DeployConfigurationParameters',
    'DiagnosticContract',
    'EmailTemplateContract',
    'EmailTemplateParametersContractProperties',
    'EmailTemplateUpdateParameters',
    'ErrorFieldContract',
    'ErrorResponse', 'ErrorResponseException',
    'ErrorResponseBody',
    'GenerateSsoUrlResult',
    'GroupContract',
    'GroupContractProperties',
    'GroupCreateParameters',
    'GroupUpdateParameters',
    'HostnameConfiguration',
    'HttpMessageDiagnostic',
    'IdentityProviderBaseParameters',
    'IdentityProviderContract',
    'IdentityProviderCreateContract',
    'IdentityProviderUpdateParameters',
    'IssueAttachmentContract',
    'IssueCommentContract',
    'IssueContract',
    'IssueContractBaseProperties',
    'IssueUpdateContract',
    'LoggerContract',
    'LoggerUpdateContract',
    'NamedValueContract',
    'NamedValueCreateContract',
    'NamedValueEntityBaseParameters',
    'NamedValueUpdateParameters',
    'NetworkStatusContract',
    'NetworkStatusContractByLocation',
    'NotificationContract',
    'OAuth2AuthenticationSettingsContract',
    'OpenIdAuthenticationSettingsContract',
    'OpenidConnectProviderContract',
    'OpenidConnectProviderCreateContract',
    'OpenidConnectProviderUpdateContract',
    'Operation',
    'OperationContract',
    'OperationDisplay',
    'OperationEntityBaseContract',
    'OperationResultContract',
    'OperationResultLogItemContract',
    'OperationTagResourceContractProperties',
    'OperationUpdateContract',
    'ParameterContract',
    'PipelineDiagnosticSettings',
    'PolicyCollection',
    'PolicyContract',
    'PolicyDescriptionCollection',
    'PolicyDescriptionContract',
    'PortalDelegationSettings',
    'PortalSettingValidationKeyContract',
    'PortalSigninSettings',
    'PortalSignupSettings',
    'ProductContract',
    'ProductEntityBaseParameters',
    'ProductTagResourceContractProperties',
    'ProductUpdateParameters',
    'PropertyValueContract',
    'QuotaCounterCollection',
    'QuotaCounterContract',
    'QuotaCounterValueContract',
    'QuotaCounterValueContractProperties',
    'RecipientEmailCollection',
    'RecipientEmailContract',
    'RecipientsContractProperties',
    'RecipientUserCollection',
    'RecipientUserContract',
    'RegionContract',
    'RegistrationDelegationSettingsProperties',
    'ReportRecordContract',
    'RepresentationContract',
    'RequestContract',
    'RequestReportRecordContract',
    'Resource',
    'ResourceSku',
    'ResourceSkuCapacity',
    'ResourceSkuResult',
    'ResponseContract',
    'SamplingSettings',
    'SaveConfigurationParameter',
    'SchemaContract',
    'SubscriptionContract',
    'SubscriptionCreateParameters',
    'SubscriptionKeyParameterNamesContract',
    'SubscriptionKeysContract',
    'SubscriptionsDelegationSettingsProperties',
    'SubscriptionUpdateParameters',
    'TagContract',
    'TagCreateUpdateParameters',
    'TagDescriptionContract',
    'TagDescriptionCreateParameters',
    'TagResourceContract',
    'TagTagResourceContractProperties',
    'TenantConfigurationSyncStateContract',
    'TermsOfServiceProperties',
    'TokenBodyParameterContract',
    'UserContract',
    'UserCreateParameters',
    'UserEntityBaseParameters',
    'UserIdentityContract',
    'UserTokenParameters',
    'UserTokenResult',
    'UserUpdateParameters',
    'VirtualNetworkConfiguration',
    'X509CertificateName',
    'ApiContractPaged',
    'TagResourceContractPaged',
    'ApiRevisionContractPaged',
    'ApiReleaseContractPaged',
    'OperationContractPaged',
    'TagContractPaged',
    'ProductContractPaged',
    'SchemaContractPaged',
    'DiagnosticContractPaged',
    'IssueContractPaged',
    'IssueCommentContractPaged',
    'IssueAttachmentContractPaged',
    'TagDescriptionContractPaged',
    'ApiVersionSetContractPaged',
    'AuthorizationServerContractPaged',
    'BackendContractPaged',
    'CacheContractPaged',
    'CertificateContractPaged',
    'OperationPaged',
    'ResourceSkuResultPaged',
    'ApiManagementServiceResourcePaged',
    'EmailTemplateContractPaged',
    'GroupContractPaged',
    'UserContractPaged',
    'IdentityProviderContractPaged',
    'LoggerContractPaged',
    'NotificationContractPaged',
    'OpenidConnectProviderContractPaged',
    'SubscriptionContractPaged',
    'NamedValueContractPaged',
    'RegionContractPaged',
    'ReportRecordContractPaged',
    'RequestReportRecordContractPaged',
    'UserIdentityContractPaged',
    'ExportResultFormat',
    'ProductState',
    'BearerTokenSendingMethods',
    'Protocol',
    'ContentFormat',
    'SoapApiType',
    'ApiType',
    'State',
    'SamplingType',
    'AlwaysLog',
    'HttpCorrelationProtocol',
    'Verbosity',
    'PolicyContentFormat',
    'VersioningScheme',
    'GrantType',
    'AuthorizationMethod',
    'ClientAuthenticationMethod',
    'BearerTokenSendingMethod',
    'BackendProtocol',
    'SkuType',
    'ResourceSkuCapacityScaleType',
    'HostnameType',
    'VirtualNetworkType',
    'ApimIdentityType',
    'NameAvailabilityReason',
    'Confirmation',
    'UserState',
    'GroupType',
    'IdentityProviderType',
    'LoggerType',
    'ConnectivityStatusType',
    'SubscriptionState',
    'AsyncOperationStatus',
    'KeyType',
    'NotificationName',
    'PolicyExportFormat',
    'TemplateName',
    'PolicyScopeContract',
    'ExportFormat',
]
