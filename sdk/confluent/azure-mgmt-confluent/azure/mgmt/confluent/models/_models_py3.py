# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import datetime
from typing import Dict, List, Optional, Union

from azure.core.exceptions import HttpResponseError
import msrest.serialization

from ._confluent_management_client_enums import *


class ConfluentAgreementResource(msrest.serialization.Model):
    """Confluent Agreements Resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: ARM id of the resource.
    :vartype id: str
    :ivar name: Name of the agreement.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param publisher: Publisher identifier string.
    :type publisher: str
    :param product: Product identifier string.
    :type product: str
    :param plan: Plan identifier string.
    :type plan: str
    :param license_text_link: Link to HTML with Microsoft and Publisher terms.
    :type license_text_link: str
    :param privacy_policy_link: Link to the privacy policy of the publisher.
    :type privacy_policy_link: str
    :param retrieve_datetime: Date and time in UTC of when the terms were accepted. This is empty
     if Accepted is false.
    :type retrieve_datetime: ~datetime.datetime
    :param signature: Terms signature.
    :type signature: str
    :param accepted: If any version of the terms have been accepted, otherwise false.
    :type accepted: bool
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'publisher': {'key': 'properties.publisher', 'type': 'str'},
        'product': {'key': 'properties.product', 'type': 'str'},
        'plan': {'key': 'properties.plan', 'type': 'str'},
        'license_text_link': {'key': 'properties.licenseTextLink', 'type': 'str'},
        'privacy_policy_link': {'key': 'properties.privacyPolicyLink', 'type': 'str'},
        'retrieve_datetime': {'key': 'properties.retrieveDatetime', 'type': 'iso-8601'},
        'signature': {'key': 'properties.signature', 'type': 'str'},
        'accepted': {'key': 'properties.accepted', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        publisher: Optional[str] = None,
        product: Optional[str] = None,
        plan: Optional[str] = None,
        license_text_link: Optional[str] = None,
        privacy_policy_link: Optional[str] = None,
        retrieve_datetime: Optional[datetime.datetime] = None,
        signature: Optional[str] = None,
        accepted: Optional[bool] = None,
        **kwargs
    ):
        super(ConfluentAgreementResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.publisher = publisher
        self.product = product
        self.plan = plan
        self.license_text_link = license_text_link
        self.privacy_policy_link = privacy_policy_link
        self.retrieve_datetime = retrieve_datetime
        self.signature = signature
        self.accepted = accepted


class ConfluentAgreementResourceListResponse(msrest.serialization.Model):
    """Response of a list operation.

    :param value: Results of a list operation.
    :type value: list[~azure.mgmt.confluent.models.ConfluentAgreementResource]
    :param next_link: Link to the next set of results, if any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[ConfluentAgreementResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["ConfluentAgreementResource"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(ConfluentAgreementResourceListResponse, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class ErrorResponseBody(msrest.serialization.Model):
    """Response body of Error.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar code: Error code.
    :vartype code: str
    :ivar message: Error message.
    :vartype message: str
    :ivar target: Error target.
    :vartype target: str
    :ivar details: Error detail.
    :vartype details: list[~azure.mgmt.confluent.models.ErrorResponseBody]
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'target': {'readonly': True},
        'details': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorResponseBody]'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ErrorResponseBody, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.target = None
        self.details = None


class OfferDetail(msrest.serialization.Model):
    """Confluent Offer detail.

    :param publisher_id: Publisher Id.
    :type publisher_id: str
    :param id: Offer Id.
    :type id: str
    :param plan_id: Offer Plan Id.
    :type plan_id: str
    :param plan_name: Offer Plan Name.
    :type plan_name: str
    :param term_unit: Offer Plan Term unit.
    :type term_unit: str
    :param status: SaaS Offer Status. Possible values include: "Started",
     "PendingFulfillmentStart", "InProgress", "Subscribed", "Suspended", "Reinstated", "Succeeded",
     "Failed", "Unsubscribed", "Updating".
    :type status: str or ~azure.mgmt.confluent.models.SaaSOfferStatus
    """

    _validation = {
        'publisher_id': {'max_length': 50, 'min_length': 0},
        'id': {'max_length': 50, 'min_length': 0},
        'plan_id': {'max_length': 50, 'min_length': 0},
        'plan_name': {'max_length': 50, 'min_length': 0},
        'term_unit': {'max_length': 25, 'min_length': 0},
    }

    _attribute_map = {
        'publisher_id': {'key': 'publisherId', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'plan_id': {'key': 'planId', 'type': 'str'},
        'plan_name': {'key': 'planName', 'type': 'str'},
        'term_unit': {'key': 'termUnit', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        publisher_id: Optional[str] = None,
        id: Optional[str] = None,
        plan_id: Optional[str] = None,
        plan_name: Optional[str] = None,
        term_unit: Optional[str] = None,
        status: Optional[Union[str, "SaaSOfferStatus"]] = None,
        **kwargs
    ):
        super(OfferDetail, self).__init__(**kwargs)
        self.publisher_id = publisher_id
        self.id = id
        self.plan_id = plan_id
        self.plan_name = plan_name
        self.term_unit = term_unit
        self.status = status


class OperationDisplay(msrest.serialization.Model):
    """The object that represents the operation.

    :param provider: Service provider: Microsoft.Confluent.
    :type provider: str
    :param resource: Type on which the operation is performed, e.g., 'clusters'.
    :type resource: str
    :param operation: Operation type, e.g., read, write, delete, etc.
    :type operation: str
    :param description: Description of the operation, e.g., 'Write confluent'.
    :type description: str
    """

    _attribute_map = {
        'provider': {'key': 'provider', 'type': 'str'},
        'resource': {'key': 'resource', 'type': 'str'},
        'operation': {'key': 'operation', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        provider: Optional[str] = None,
        resource: Optional[str] = None,
        operation: Optional[str] = None,
        description: Optional[str] = None,
        **kwargs
    ):
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description


class OperationListResult(msrest.serialization.Model):
    """Result of GET request to list Confluent operations.

    :param value: List of Confluent operations supported by the Microsoft.Confluent provider.
    :type value: list[~azure.mgmt.confluent.models.OperationResult]
    :param next_link: URL to get the next set of operation list results if there are any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[OperationResult]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["OperationResult"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(OperationListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class OperationResult(msrest.serialization.Model):
    """An Confluent REST API operation.

    :param name: Operation name: {provider}/{resource}/{operation}.
    :type name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.confluent.models.OperationDisplay
    :param is_data_action: Indicates whether the operation is a data action.
    :type is_data_action: bool
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
        'is_data_action': {'key': 'isDataAction', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        display: Optional["OperationDisplay"] = None,
        is_data_action: Optional[bool] = None,
        **kwargs
    ):
        super(OperationResult, self).__init__(**kwargs)
        self.name = name
        self.display = display
        self.is_data_action = is_data_action


class OrganizationResource(msrest.serialization.Model):
    """Organization resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: The ARM id of the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :param tags: A set of tags. Organization resource tags.
    :type tags: dict[str, str]
    :param location: Location of Organization resource.
    :type location: str
    :ivar created_time: The creation time of the resource.
    :vartype created_time: ~datetime.datetime
    :param provisioning_state: Provision states for confluent RP. Possible values include:
     "Accepted", "Creating", "Updating", "Deleting", "Succeeded", "Failed", "Canceled", "Deleted",
     "NotSpecified".
    :type provisioning_state: str or ~azure.mgmt.confluent.models.ProvisionState
    :ivar organization_id: Id of the Confluent organization.
    :vartype organization_id: str
    :ivar sso_url: SSO url for the Confluent organization.
    :vartype sso_url: str
    :param offer_detail: Confluent offer detail.
    :type offer_detail: ~azure.mgmt.confluent.models.OfferDetail
    :param user_detail: Subscriber detail.
    :type user_detail: ~azure.mgmt.confluent.models.UserDetail
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'created_time': {'readonly': True},
        'organization_id': {'readonly': True},
        'sso_url': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
        'created_time': {'key': 'properties.createdTime', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'organization_id': {'key': 'properties.organizationId', 'type': 'str'},
        'sso_url': {'key': 'properties.ssoUrl', 'type': 'str'},
        'offer_detail': {'key': 'properties.offerDetail', 'type': 'OfferDetail'},
        'user_detail': {'key': 'properties.userDetail', 'type': 'UserDetail'},
    }

    def __init__(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        location: Optional[str] = None,
        provisioning_state: Optional[Union[str, "ProvisionState"]] = None,
        offer_detail: Optional["OfferDetail"] = None,
        user_detail: Optional["UserDetail"] = None,
        **kwargs
    ):
        super(OrganizationResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.tags = tags
        self.location = location
        self.created_time = None
        self.provisioning_state = provisioning_state
        self.organization_id = None
        self.sso_url = None
        self.offer_detail = offer_detail
        self.user_detail = user_detail


class OrganizationResourceListResult(msrest.serialization.Model):
    """The response of a list operation.

    :param value: Result of a list operation.
    :type value: list[~azure.mgmt.confluent.models.OrganizationResource]
    :param next_link: Link to the next set of results, if any.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[OrganizationResource]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["OrganizationResource"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(OrganizationResourceListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class OrganizationResourceProperties(msrest.serialization.Model):
    """Organization resource property.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar created_time: The creation time of the resource.
    :vartype created_time: ~datetime.datetime
    :param provisioning_state: Provision states for confluent RP. Possible values include:
     "Accepted", "Creating", "Updating", "Deleting", "Succeeded", "Failed", "Canceled", "Deleted",
     "NotSpecified".
    :type provisioning_state: str or ~azure.mgmt.confluent.models.ProvisionState
    :ivar organization_id: Id of the Confluent organization.
    :vartype organization_id: str
    :ivar sso_url: SSO url for the Confluent organization.
    :vartype sso_url: str
    :param offer_detail: Confluent offer detail.
    :type offer_detail: ~azure.mgmt.confluent.models.OfferDetail
    :param user_detail: Subscriber detail.
    :type user_detail: ~azure.mgmt.confluent.models.UserDetail
    """

    _validation = {
        'created_time': {'readonly': True},
        'organization_id': {'readonly': True},
        'sso_url': {'readonly': True},
    }

    _attribute_map = {
        'created_time': {'key': 'createdTime', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'organization_id': {'key': 'organizationId', 'type': 'str'},
        'sso_url': {'key': 'ssoUrl', 'type': 'str'},
        'offer_detail': {'key': 'offerDetail', 'type': 'OfferDetail'},
        'user_detail': {'key': 'userDetail', 'type': 'UserDetail'},
    }

    def __init__(
        self,
        *,
        provisioning_state: Optional[Union[str, "ProvisionState"]] = None,
        offer_detail: Optional["OfferDetail"] = None,
        user_detail: Optional["UserDetail"] = None,
        **kwargs
    ):
        super(OrganizationResourceProperties, self).__init__(**kwargs)
        self.created_time = None
        self.provisioning_state = provisioning_state
        self.organization_id = None
        self.sso_url = None
        self.offer_detail = offer_detail
        self.user_detail = user_detail


class OrganizationResourcePropertiesAutoGenerated(OrganizationResourceProperties):
    """Organization resource properties.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar created_time: The creation time of the resource.
    :vartype created_time: ~datetime.datetime
    :param provisioning_state: Provision states for confluent RP. Possible values include:
     "Accepted", "Creating", "Updating", "Deleting", "Succeeded", "Failed", "Canceled", "Deleted",
     "NotSpecified".
    :type provisioning_state: str or ~azure.mgmt.confluent.models.ProvisionState
    :ivar organization_id: Id of the Confluent organization.
    :vartype organization_id: str
    :ivar sso_url: SSO url for the Confluent organization.
    :vartype sso_url: str
    :param offer_detail: Confluent offer detail.
    :type offer_detail: ~azure.mgmt.confluent.models.OfferDetail
    :param user_detail: Subscriber detail.
    :type user_detail: ~azure.mgmt.confluent.models.UserDetail
    """

    _validation = {
        'created_time': {'readonly': True},
        'organization_id': {'readonly': True},
        'sso_url': {'readonly': True},
    }

    _attribute_map = {
        'created_time': {'key': 'createdTime', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'organization_id': {'key': 'organizationId', 'type': 'str'},
        'sso_url': {'key': 'ssoUrl', 'type': 'str'},
        'offer_detail': {'key': 'offerDetail', 'type': 'OfferDetail'},
        'user_detail': {'key': 'userDetail', 'type': 'UserDetail'},
    }

    def __init__(
        self,
        *,
        provisioning_state: Optional[Union[str, "ProvisionState"]] = None,
        offer_detail: Optional["OfferDetail"] = None,
        user_detail: Optional["UserDetail"] = None,
        **kwargs
    ):
        super(OrganizationResourcePropertiesAutoGenerated, self).__init__(provisioning_state=provisioning_state, offer_detail=offer_detail, user_detail=user_detail, **kwargs)


class OrganizationResourcePropertiesOfferDetail(OfferDetail):
    """Confluent offer detail.

    :param publisher_id: Publisher Id.
    :type publisher_id: str
    :param id: Offer Id.
    :type id: str
    :param plan_id: Offer Plan Id.
    :type plan_id: str
    :param plan_name: Offer Plan Name.
    :type plan_name: str
    :param term_unit: Offer Plan Term unit.
    :type term_unit: str
    :param status: SaaS Offer Status. Possible values include: "Started",
     "PendingFulfillmentStart", "InProgress", "Subscribed", "Suspended", "Reinstated", "Succeeded",
     "Failed", "Unsubscribed", "Updating".
    :type status: str or ~azure.mgmt.confluent.models.SaaSOfferStatus
    """

    _validation = {
        'publisher_id': {'max_length': 50, 'min_length': 0},
        'id': {'max_length': 50, 'min_length': 0},
        'plan_id': {'max_length': 50, 'min_length': 0},
        'plan_name': {'max_length': 50, 'min_length': 0},
        'term_unit': {'max_length': 25, 'min_length': 0},
    }

    _attribute_map = {
        'publisher_id': {'key': 'publisherId', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'plan_id': {'key': 'planId', 'type': 'str'},
        'plan_name': {'key': 'planName', 'type': 'str'},
        'term_unit': {'key': 'termUnit', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        publisher_id: Optional[str] = None,
        id: Optional[str] = None,
        plan_id: Optional[str] = None,
        plan_name: Optional[str] = None,
        term_unit: Optional[str] = None,
        status: Optional[Union[str, "SaaSOfferStatus"]] = None,
        **kwargs
    ):
        super(OrganizationResourcePropertiesOfferDetail, self).__init__(publisher_id=publisher_id, id=id, plan_id=plan_id, plan_name=plan_name, term_unit=term_unit, status=status, **kwargs)


class UserDetail(msrest.serialization.Model):
    """Subscriber detail.

    :param first_name: First name.
    :type first_name: str
    :param last_name: Last name.
    :type last_name: str
    :param email_address: Email address.
    :type email_address: str
    """

    _validation = {
        'first_name': {'max_length': 50, 'min_length': 0},
        'last_name': {'max_length': 50, 'min_length': 0},
        'email_address': {'pattern': r'\S+@\S+\.\S+'},
    }

    _attribute_map = {
        'first_name': {'key': 'firstName', 'type': 'str'},
        'last_name': {'key': 'lastName', 'type': 'str'},
        'email_address': {'key': 'emailAddress', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email_address: Optional[str] = None,
        **kwargs
    ):
        super(UserDetail, self).__init__(**kwargs)
        self.first_name = first_name
        self.last_name = last_name
        self.email_address = email_address


class OrganizationResourcePropertiesUserDetail(UserDetail):
    """Subscriber detail.

    :param first_name: First name.
    :type first_name: str
    :param last_name: Last name.
    :type last_name: str
    :param email_address: Email address.
    :type email_address: str
    """

    _validation = {
        'first_name': {'max_length': 50, 'min_length': 0},
        'last_name': {'max_length': 50, 'min_length': 0},
        'email_address': {'pattern': r'\S+@\S+\.\S+'},
    }

    _attribute_map = {
        'first_name': {'key': 'firstName', 'type': 'str'},
        'last_name': {'key': 'lastName', 'type': 'str'},
        'email_address': {'key': 'emailAddress', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email_address: Optional[str] = None,
        **kwargs
    ):
        super(OrganizationResourcePropertiesUserDetail, self).__init__(first_name=first_name, last_name=last_name, email_address=email_address, **kwargs)


class OrganizationResourceUpdate(msrest.serialization.Model):
    """Organization Resource update.

    :param tags: A set of tags. ARM resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(OrganizationResourceUpdate, self).__init__(**kwargs)
        self.tags = tags


class ResourceProviderDefaultErrorResponse(msrest.serialization.Model):
    """Default error response for resource provider.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar error: Response body of Error.
    :vartype error: ~azure.mgmt.confluent.models.ErrorResponseBody
    """

    _validation = {
        'error': {'readonly': True},
    }

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponseBody'},
    }

    def __init__(
        self,
        **kwargs
    ):
        super(ResourceProviderDefaultErrorResponse, self).__init__(**kwargs)
        self.error = None
