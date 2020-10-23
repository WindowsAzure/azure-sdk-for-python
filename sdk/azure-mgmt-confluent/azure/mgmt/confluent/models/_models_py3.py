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
from msrest.exceptions import HttpOperationError


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class ErrorResponseBody(Model):
    """ErrorResponseBody.

    Response body of Error.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar code: Error code
    :vartype code: str
    :ivar message: Error message
    :vartype message: str
    :ivar target: Error target
    :vartype target: str
    :ivar details: Error detail
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

    def __init__(self, **kwargs) -> None:
        super(ErrorResponseBody, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.target = None
        self.details = None


class OfferDetail(Model):
    """Confluent Offer detail.

    :param publisher_id: Publisher Id
    :type publisher_id: str
    :param id: Offer Id
    :type id: str
    :param plan_id: Offer Plan Id
    :type plan_id: str
    :param plan_name: Offer Plan Name
    :type plan_name: str
    :param term_unit: Offer Plan Term unit
    :type term_unit: str
    :param status: SaaS Offer Status. Possible values include: 'Started',
     'PendingFulfillmentStart', 'InProgress', 'Subscribed', 'Suspended',
     'Reinstated', 'Succeeded', 'Failed', 'Unsubscribed', 'Updating'
    :type status: str or ~azure.mgmt.confluent.models.SaaSOfferStatus
    """

    _validation = {
        'publisher_id': {'max_length': 50},
        'id': {'max_length': 50},
        'plan_id': {'max_length': 50},
        'plan_name': {'max_length': 50},
        'term_unit': {'max_length': 25},
    }

    _attribute_map = {
        'publisher_id': {'key': 'publisherId', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'plan_id': {'key': 'planId', 'type': 'str'},
        'plan_name': {'key': 'planName', 'type': 'str'},
        'term_unit': {'key': 'termUnit', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(self, *, publisher_id: str=None, id: str=None, plan_id: str=None, plan_name: str=None, term_unit: str=None, status=None, **kwargs) -> None:
        super(OfferDetail, self).__init__(**kwargs)
        self.publisher_id = publisher_id
        self.id = id
        self.plan_id = plan_id
        self.plan_name = plan_name
        self.term_unit = term_unit
        self.status = status


class OperationDisplay(Model):
    """The object that represents the operation.

    :param provider: Service provider: Microsoft.Confluent
    :type provider: str
    :param resource: Type on which the operation is performed, e.g.,
     'clusters'.
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

    def __init__(self, *, provider: str=None, resource: str=None, operation: str=None, description: str=None, **kwargs) -> None:
        super(OperationDisplay, self).__init__(**kwargs)
        self.provider = provider
        self.resource = resource
        self.operation = operation
        self.description = description


class OperationResult(Model):
    """An Confluent REST API operation.

    :param name: Operation name: {provider}/{resource}/{operation}
    :type name: str
    :param display: The object that represents the operation.
    :type display: ~azure.mgmt.confluent.models.OperationDisplay
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'display': {'key': 'display', 'type': 'OperationDisplay'},
    }

    def __init__(self, *, name: str=None, display=None, **kwargs) -> None:
        super(OperationResult, self).__init__(**kwargs)
        self.name = name
        self.display = display


class OrganizationResource(Model):
    """Organization resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: The ARM id of the resource.
    :vartype id: str
    :ivar name: The name of the resource.
    :vartype name: str
    :ivar type: The type of the resource.
    :vartype type: str
    :ivar created_time: The creation time of the resource.
    :vartype created_time: datetime
    :param provisioning_state: Provision states for confluent RP. Possible
     values include: 'Accepted', 'Creating', 'Updating', 'Deleting',
     'Succeeded', 'Failed', 'Canceled', 'Deleted', 'NotSpecified'
    :type provisioning_state: str or
     ~azure.mgmt.confluent.models.ProvisionState
    :ivar organization_id: Id of the Confluent organization.
    :vartype organization_id: str
    :ivar sso_url: SSO url for the Confluent organization.
    :vartype sso_url: str
    :param offer_detail: Confluent offer detail
    :type offer_detail:
     ~azure.mgmt.confluent.models.OrganizationResourcePropertiesOfferDetail
    :param user_detail: Subscriber detail
    :type user_detail:
     ~azure.mgmt.confluent.models.OrganizationResourcePropertiesUserDetail
    :param tags: Organization resource tags
    :type tags: dict[str, str]
    :param location: Location of Organization resource
    :type location: str
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
        'created_time': {'key': 'properties.createdTime', 'type': 'iso-8601'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'organization_id': {'key': 'properties.organizationId', 'type': 'str'},
        'sso_url': {'key': 'properties.ssoUrl', 'type': 'str'},
        'offer_detail': {'key': 'properties.offerDetail', 'type': 'OrganizationResourcePropertiesOfferDetail'},
        'user_detail': {'key': 'properties.userDetail', 'type': 'OrganizationResourcePropertiesUserDetail'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'location': {'key': 'location', 'type': 'str'},
    }

    def __init__(self, *, provisioning_state=None, offer_detail=None, user_detail=None, tags=None, location: str=None, **kwargs) -> None:
        super(OrganizationResource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.created_time = None
        self.provisioning_state = provisioning_state
        self.organization_id = None
        self.sso_url = None
        self.offer_detail = offer_detail
        self.user_detail = user_detail
        self.tags = tags
        self.location = location


class OrganizationResourceProperties(Model):
    """Organization resource property.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar created_time: The creation time of the resource.
    :vartype created_time: datetime
    :param provisioning_state: Provision states for confluent RP. Possible
     values include: 'Accepted', 'Creating', 'Updating', 'Deleting',
     'Succeeded', 'Failed', 'Canceled', 'Deleted', 'NotSpecified'
    :type provisioning_state: str or
     ~azure.mgmt.confluent.models.ProvisionState
    :ivar organization_id: Id of the Confluent organization.
    :vartype organization_id: str
    :ivar sso_url: SSO url for the Confluent organization.
    :vartype sso_url: str
    :param offer_detail: Confluent offer detail
    :type offer_detail:
     ~azure.mgmt.confluent.models.OrganizationResourcePropertiesOfferDetail
    :param user_detail: Subscriber detail
    :type user_detail:
     ~azure.mgmt.confluent.models.OrganizationResourcePropertiesUserDetail
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
        'offer_detail': {'key': 'offerDetail', 'type': 'OrganizationResourcePropertiesOfferDetail'},
        'user_detail': {'key': 'userDetail', 'type': 'OrganizationResourcePropertiesUserDetail'},
    }

    def __init__(self, *, provisioning_state=None, offer_detail=None, user_detail=None, **kwargs) -> None:
        super(OrganizationResourceProperties, self).__init__(**kwargs)
        self.created_time = None
        self.provisioning_state = provisioning_state
        self.organization_id = None
        self.sso_url = None
        self.offer_detail = offer_detail
        self.user_detail = user_detail


class OrganizationResourcePropertiesOfferDetail(OfferDetail):
    """Confluent offer detail.

    :param publisher_id: Publisher Id
    :type publisher_id: str
    :param id: Offer Id
    :type id: str
    :param plan_id: Offer Plan Id
    :type plan_id: str
    :param plan_name: Offer Plan Name
    :type plan_name: str
    :param term_unit: Offer Plan Term unit
    :type term_unit: str
    :param status: SaaS Offer Status. Possible values include: 'Started',
     'PendingFulfillmentStart', 'InProgress', 'Subscribed', 'Suspended',
     'Reinstated', 'Succeeded', 'Failed', 'Unsubscribed', 'Updating'
    :type status: str or ~azure.mgmt.confluent.models.SaaSOfferStatus
    """

    _validation = {
        'publisher_id': {'max_length': 50},
        'id': {'max_length': 50},
        'plan_id': {'max_length': 50},
        'plan_name': {'max_length': 50},
        'term_unit': {'max_length': 25},
    }

    _attribute_map = {
        'publisher_id': {'key': 'publisherId', 'type': 'str'},
        'id': {'key': 'id', 'type': 'str'},
        'plan_id': {'key': 'planId', 'type': 'str'},
        'plan_name': {'key': 'planName', 'type': 'str'},
        'term_unit': {'key': 'termUnit', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
    }

    def __init__(self, *, publisher_id: str=None, id: str=None, plan_id: str=None, plan_name: str=None, term_unit: str=None, status=None, **kwargs) -> None:
        super(OrganizationResourcePropertiesOfferDetail, self).__init__(publisher_id=publisher_id, id=id, plan_id=plan_id, plan_name=plan_name, term_unit=term_unit, status=status, **kwargs)


class UserDetail(Model):
    """Subscriber detail.

    :param first_name: First name
    :type first_name: str
    :param last_name: Last name
    :type last_name: str
    :param email_address: Email address
    :type email_address: str
    """

    _validation = {
        'first_name': {'max_length': 50},
        'last_name': {'max_length': 50},
        'email_address': {'pattern': r'^[\w\.\-+!%"\s]+@[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9]{2,7}$'},
    }

    _attribute_map = {
        'first_name': {'key': 'firstName', 'type': 'str'},
        'last_name': {'key': 'lastName', 'type': 'str'},
        'email_address': {'key': 'emailAddress', 'type': 'str'},
    }

    def __init__(self, *, first_name: str=None, last_name: str=None, email_address: str=None, **kwargs) -> None:
        super(UserDetail, self).__init__(**kwargs)
        self.first_name = first_name
        self.last_name = last_name
        self.email_address = email_address


class OrganizationResourcePropertiesUserDetail(UserDetail):
    """Subscriber detail.

    :param first_name: First name
    :type first_name: str
    :param last_name: Last name
    :type last_name: str
    :param email_address: Email address
    :type email_address: str
    """

    _validation = {
        'first_name': {'max_length': 50},
        'last_name': {'max_length': 50},
        'email_address': {'pattern': r'^[\w\.\-+!%"\s]+@[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9]{2,7}$'},
    }

    _attribute_map = {
        'first_name': {'key': 'firstName', 'type': 'str'},
        'last_name': {'key': 'lastName', 'type': 'str'},
        'email_address': {'key': 'emailAddress', 'type': 'str'},
    }

    def __init__(self, *, first_name: str=None, last_name: str=None, email_address: str=None, **kwargs) -> None:
        super(OrganizationResourcePropertiesUserDetail, self).__init__(first_name=first_name, last_name=last_name, email_address=email_address, **kwargs)


class OrganizationResourceUpdate(Model):
    """Organization Resource update.

    :param tags: ARM resource tags
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(self, *, tags=None, **kwargs) -> None:
        super(OrganizationResourceUpdate, self).__init__(**kwargs)
        self.tags = tags


class ResourceProviderDefaultErrorResponse(Model):
    """ResourceProviderDefaultErrorResponse.

    Default error response for resource provider.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar error: Response body of Error
    :vartype error: ~azure.mgmt.confluent.models.ErrorResponseBody
    """

    _validation = {
        'error': {'readonly': True},
    }

    _attribute_map = {
        'error': {'key': 'error', 'type': 'ErrorResponseBody'},
    }

    def __init__(self, **kwargs) -> None:
        super(ResourceProviderDefaultErrorResponse, self).__init__(**kwargs)
        self.error = None


class ResourceProviderDefaultErrorResponseException(HttpOperationError):
    """Server responsed with exception of type: 'ResourceProviderDefaultErrorResponse'.

    :param deserialize: A deserializer
    :param response: Server response to be deserialized.
    """

    def __init__(self, deserialize, response, *args):

        super(ResourceProviderDefaultErrorResponseException, self).__init__(deserialize, response, 'ResourceProviderDefaultErrorResponse', *args)
