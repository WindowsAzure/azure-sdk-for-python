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


class ExportResultFormat(str, Enum):

    swagger = "swagger-link-json"  #: The Api Definition is exported in OpenApi Specification 2.0 format to the Storage Blob.
    wsdl = "wsdl-link+xml"  #: The Api Definition is exported in WSDL Schema to Storage Blob. This is only supported for APIs of Type `soap`
    wadl = "wadl-link-json"  #: Export the Api Definition in WADL Schema to Storage Blob.
    open_api = "openapi-link"  #: Export the Api Definition in OpenApi Specification 3.0 to Storage Blob.


class ProductState(str, Enum):

    not_published = "notPublished"
    published = "published"


class BearerTokenSendingMethods(str, Enum):

    authorization_header = "authorizationHeader"  #: Access token will be transmitted in the Authorization header using Bearer schema
    query = "query"  #: Access token will be transmitted as query parameters.


class Protocol(str, Enum):

    http = "http"
    https = "https"


class ContentFormat(str, Enum):

    wadl_xml = "wadl-xml"  #: The contents are inline and Content type is a WADL document.
    wadl_link_json = "wadl-link-json"  #: The WADL document is hosted on a publicly accessible internet address.
    swagger_json = "swagger-json"  #: The contents are inline and Content Type is a OpenApi 2.0 Document.
    swagger_link_json = "swagger-link-json"  #: The Open Api 2.0 document is hosted on a publicly accessible internet address.
    wsdl = "wsdl"  #: The contents are inline and the document is a WSDL/Soap document.
    wsdl_link = "wsdl-link"  #: The WSDL document is hosted on a publicly accessible internet address.
    openapi = "openapi"  #: The contents are inline and Content Type is a OpenApi 3.0 Document in YAML format.
    openapijson = "openapi+json"  #: The contents are inline and Content Type is a OpenApi 3.0 Document in JSON format.
    openapi_link = "openapi-link"  #: The Open Api 3.0 document is hosted on a publicly accessible internet address.


class SoapApiType(str, Enum):

    soap_to_rest = "http"  #: Imports a SOAP API having a RESTful front end.
    soap_pass_through = "soap"  #: Imports the Soap API having a SOAP front end.


class ApiType(str, Enum):

    http = "http"
    soap = "soap"


class State(str, Enum):

    proposed = "proposed"  #: The issue is proposed.
    open = "open"  #: The issue is opened.
    removed = "removed"  #: The issue was removed.
    resolved = "resolved"  #: The issue is now resolved.
    closed = "closed"  #: The issue was closed.


class SamplingType(str, Enum):

    fixed = "fixed"  #: Fixed-rate sampling.


class AlwaysLog(str, Enum):

    all_errors = "allErrors"  #: Always log all erroneous request regardless of sampling settings.


class PolicyContentFormat(str, Enum):

    xml = "xml"  #: The contents are inline and Content type is an XML document.
    xml_link = "xml-link"  #: The policy XML document is hosted on a http endpoint accessible from the API Management service.
    rawxml = "rawxml"  #: The contents are inline and Content type is a non XML encoded policy document.
    rawxml_link = "rawxml-link"  #: The policy document is not Xml encoded and is hosted on a http endpoint accessible from the API Management service.


class VersioningScheme(str, Enum):

    segment = "Segment"  #: The API Version is passed in a path segment.
    query = "Query"  #: The API Version is passed in a query parameter.
    header = "Header"  #: The API Version is passed in a HTTP header.


class GrantType(str, Enum):

    authorization_code = "authorizationCode"  #: Authorization Code Grant flow as described https://tools.ietf.org/html/rfc6749#section-4.1.
    implicit = "implicit"  #: Implicit Code Grant flow as described https://tools.ietf.org/html/rfc6749#section-4.2.
    resource_owner_password = "resourceOwnerPassword"  #: Resource Owner Password Grant flow as described https://tools.ietf.org/html/rfc6749#section-4.3.
    client_credentials = "clientCredentials"  #: Client Credentials Grant flow as described https://tools.ietf.org/html/rfc6749#section-4.4.


class AuthorizationMethod(str, Enum):

    head = "HEAD"
    options = "OPTIONS"
    trace = "TRACE"
    get = "GET"
    post = "POST"
    put = "PUT"
    patch = "PATCH"
    delete = "DELETE"


class ClientAuthenticationMethod(str, Enum):

    basic = "Basic"  #: Basic Client Authentication method.
    body = "Body"  #: Body based Authentication method.


class BearerTokenSendingMethod(str, Enum):

    authorization_header = "authorizationHeader"
    query = "query"


class BackendProtocol(str, Enum):

    http = "http"  #: The Backend is a RESTful service.
    soap = "soap"  #: The Backend is a SOAP service.


class SkuType(str, Enum):

    developer = "Developer"  #: Developer SKU of Api Management.
    standard = "Standard"  #: Standard SKU of Api Management.
    premium = "Premium"  #: Premium SKU of Api Management.
    basic = "Basic"  #: Basic SKU of Api Management.
    consumption = "Consumption"  #: Consumption SKU of Api Management.


class ResourceSkuCapacityScaleType(str, Enum):

    automatic = "automatic"  #: Supported scale type automatic.
    manual = "manual"  #: Supported scale type manual.
    none = "none"  #: Scaling not supported.


class HostnameType(str, Enum):

    proxy = "Proxy"
    portal = "Portal"
    management = "Management"
    scm = "Scm"
    developer_portal = "DeveloperPortal"


class VirtualNetworkType(str, Enum):

    none = "None"  #: The service is not part of any Virtual Network.
    external = "External"  #: The service is part of Virtual Network and it is accessible from Internet.
    internal = "Internal"  #: The service is part of Virtual Network and it is only accessible from within the virtual network.


class NameAvailabilityReason(str, Enum):

    valid = "Valid"
    invalid = "Invalid"
    already_exists = "AlreadyExists"


class Confirmation(str, Enum):

    signup = "signup"  #: Send an e-mail to the user confirming they have successfully signed up.
    invite = "invite"  #: Send an e-mail inviting the user to sign-up and complete registration.


class UserState(str, Enum):

    active = "active"  #: User state is active.
    blocked = "blocked"  #: User is blocked. Blocked users cannot authenticate at developer portal or call API.
    pending = "pending"  #: User account is pending. Requires identity confirmation before it can be made active.
    deleted = "deleted"  #: User account is closed. All identities and related entities are removed.


class GroupType(str, Enum):

    custom = "custom"
    system = "system"
    external = "external"


class IdentityProviderType(str, Enum):

    facebook = "facebook"  #: Facebook as Identity provider.
    google = "google"  #: Google as Identity provider.
    microsoft = "microsoft"  #: Microsoft Live as Identity provider.
    twitter = "twitter"  #: Twitter as Identity provider.
    aad = "aad"  #: Azure Active Directory as Identity provider.
    aad_b2_c = "aadB2C"  #: Azure Active Directory B2C as Identity provider.


class LoggerType(str, Enum):

    azure_event_hub = "azureEventHub"  #: Azure Event Hub as log destination.
    application_insights = "applicationInsights"  #: Azure Application Insights as log destination.


class ConnectivityStatusType(str, Enum):

    initializing = "initializing"
    success = "success"
    failure = "failure"


class SubscriptionState(str, Enum):

    suspended = "suspended"
    active = "active"
    expired = "expired"
    submitted = "submitted"
    rejected = "rejected"
    cancelled = "cancelled"


class AsyncOperationStatus(str, Enum):

    started = "Started"
    in_progress = "InProgress"
    succeeded = "Succeeded"
    failed = "Failed"


class KeyType(str, Enum):

    primary = "primary"
    secondary = "secondary"


class NotificationName(str, Enum):

    request_publisher_notification_message = "RequestPublisherNotificationMessage"  #: The following email recipients and users will receive email notifications about subscription requests for API products requiring approval.
    purchase_publisher_notification_message = "PurchasePublisherNotificationMessage"  #: The following email recipients and users will receive email notifications about new API product subscriptions.
    new_application_notification_message = "NewApplicationNotificationMessage"  #: The following email recipients and users will receive email notifications when new applications are submitted to the application gallery.
    bcc = "BCC"  #: The following recipients will receive blind carbon copies of all emails sent to developers.
    new_issue_publisher_notification_message = "NewIssuePublisherNotificationMessage"  #: The following email recipients and users will receive email notifications when a new issue or comment is submitted on the developer portal.
    account_closed_publisher = "AccountClosedPublisher"  #: The following email recipients and users will receive email notifications when developer closes his account.
    quota_limit_approaching_publisher_notification_message = "QuotaLimitApproachingPublisherNotificationMessage"  #: The following email recipients and users will receive email notifications when subscription usage gets close to usage quota.


class PolicyExportFormat(str, Enum):

    xml = "xml"  #: The contents are inline and Content type is an XML document.
    rawxml = "rawxml"  #: The contents are inline and Content type is a non XML encoded policy document.


class TemplateName(str, Enum):

    application_approved_notification_message = "applicationApprovedNotificationMessage"
    account_closed_developer = "accountClosedDeveloper"
    quota_limit_approaching_developer_notification_message = "quotaLimitApproachingDeveloperNotificationMessage"
    new_developer_notification_message = "newDeveloperNotificationMessage"
    email_change_identity_default = "emailChangeIdentityDefault"
    invite_user_notification_message = "inviteUserNotificationMessage"
    new_comment_notification_message = "newCommentNotificationMessage"
    confirm_sign_up_identity_default = "confirmSignUpIdentityDefault"
    new_issue_notification_message = "newIssueNotificationMessage"
    purchase_developer_notification_message = "purchaseDeveloperNotificationMessage"
    password_reset_identity_default = "passwordResetIdentityDefault"
    password_reset_by_admin_notification_message = "passwordResetByAdminNotificationMessage"
    reject_developer_notification_message = "rejectDeveloperNotificationMessage"
    request_developer_notification_message = "requestDeveloperNotificationMessage"


class PolicyScopeContract(str, Enum):

    tenant = "Tenant"
    product = "Product"
    api = "Api"
    operation = "Operation"
    all = "All"


class ExportFormat(str, Enum):

    swagger = "swagger-link"  #: Export the Api Definition in OpenApi Specification 2.0 format to the Storage Blob.
    wsdl = "wsdl-link"  #: Export the Api Definition in WSDL Schema to Storage Blob. This is only supported for APIs of Type `soap`
    wadl = "wadl-link"  #: Export the Api Definition in WADL Schema to Storage Blob.
    openapi = "openapi-link"  #: Export the Api Definition in OpenApi Specification 3.0 to Storage Blob.
