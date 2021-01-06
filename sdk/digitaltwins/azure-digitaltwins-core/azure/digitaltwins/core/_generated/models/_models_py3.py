# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

import datetime
from typing import Dict, List, Optional

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class DigitalTwinModelsAddOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinModelsAddOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinModelsDeleteOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinModelsDeleteOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinModelsGetByIdOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinModelsGetByIdOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinModelsListOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param max_items_per_page: The maximum number of items to retrieve per request. The server may
     choose to return less than the requested number.
    :type max_items_per_page: int
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'max_items_per_page': {'key': 'MaxItemsPerPage', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        max_items_per_page: Optional[int] = None,
        **kwargs
    ):
        super(DigitalTwinModelsListOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.max_items_per_page = max_items_per_page


class DigitalTwinModelsUpdateOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinModelsUpdateOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinsAddOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param if_none_match: Only perform the operation if the entity does not already exist.
    :type if_none_match: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'if_none_match': {'key': 'If-None-Match', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        if_none_match: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsAddOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.if_none_match = if_none_match


class DigitalTwinsAddRelationshipOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param if_none_match: Only perform the operation if the entity does not already exist.
    :type if_none_match: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'if_none_match': {'key': 'If-None-Match', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        if_none_match: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsAddRelationshipOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.if_none_match = if_none_match


class DigitalTwinsDeleteOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param if_match: Only perform the operation if the entity's etag matches one of the etags
     provided or * is provided.
    :type if_match: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'if_match': {'key': 'If-Match', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        if_match: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsDeleteOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.if_match = if_match


class DigitalTwinsDeleteRelationshipOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param if_match: Only perform the operation if the entity's etag matches one of the etags
     provided or * is provided.
    :type if_match: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'if_match': {'key': 'If-Match', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        if_match: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsDeleteRelationshipOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.if_match = if_match


class DigitalTwinsEventRoute(msrest.serialization.Model):
    """A route which directs notification and telemetry events to an endpoint. Endpoints are a destination outside of Azure Digital Twins such as an EventHub.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: The id of the event route.
    :vartype id: str
    :param endpoint_name: Required. The name of the endpoint this event route is bound to.
    :type endpoint_name: str
    :param filter: Required. An expression which describes the events which are routed to the
     endpoint.
    :type filter: str
    """

    _validation = {
        'id': {'readonly': True},
        'endpoint_name': {'required': True},
        'filter': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'endpoint_name': {'key': 'endpointName', 'type': 'str'},
        'filter': {'key': 'filter', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        endpoint_name: str,
        filter: str,
        **kwargs
    ):
        super(DigitalTwinsEventRoute, self).__init__(**kwargs)
        self.id = None
        self.endpoint_name = endpoint_name
        self.filter = filter


class DigitalTwinsGetByIdOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsGetByIdOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinsGetComponentOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsGetComponentOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinsGetRelationshipByIdOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsGetRelationshipByIdOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinsListIncomingRelationshipsOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsListIncomingRelationshipsOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinsListRelationshipsOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsListRelationshipsOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinsModelData(msrest.serialization.Model):
    """A model definition and metadata for that model.

    All required parameters must be populated in order to send to Azure.

    :param display_name: A language map that contains the localized display names as specified in
     the model definition.
    :type display_name: dict[str, str]
    :param description: A language map that contains the localized descriptions as specified in the
     model definition.
    :type description: dict[str, str]
    :param id: Required. The id of the model as specified in the model definition.
    :type id: str
    :param upload_time: The time the model was uploaded to the service.
    :type upload_time: ~datetime.datetime
    :param decommissioned: Indicates if the model is decommissioned. Decommissioned models cannot
     be referenced by newly created digital twins.
    :type decommissioned: bool
    :param model: The model definition.
    :type model: object
    """

    _validation = {
        'id': {'required': True},
    }

    _attribute_map = {
        'display_name': {'key': 'displayName', 'type': '{str}'},
        'description': {'key': 'description', 'type': '{str}'},
        'id': {'key': 'id', 'type': 'str'},
        'upload_time': {'key': 'uploadTime', 'type': 'iso-8601'},
        'decommissioned': {'key': 'decommissioned', 'type': 'bool'},
        'model': {'key': 'model', 'type': 'object'},
    }

    def __init__(
        self,
        *,
        id: str,
        display_name: Optional[Dict[str, str]] = None,
        description: Optional[Dict[str, str]] = None,
        upload_time: Optional[datetime.datetime] = None,
        decommissioned: Optional[bool] = False,
        model: Optional[object] = None,
        **kwargs
    ):
        super(DigitalTwinsModelData, self).__init__(**kwargs)
        self.display_name = display_name
        self.description = description
        self.id = id
        self.upload_time = upload_time
        self.decommissioned = decommissioned
        self.model = model


class DigitalTwinsSendComponentTelemetryOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsSendComponentTelemetryOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinsSendTelemetryOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsSendTelemetryOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class DigitalTwinsUpdateComponentOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param if_match: Only perform the operation if the entity's etag matches one of the etags
     provided or * is provided.
    :type if_match: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'if_match': {'key': 'If-Match', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        if_match: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsUpdateComponentOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.if_match = if_match


class DigitalTwinsUpdateOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param if_match: Only perform the operation if the entity's etag matches one of the etags
     provided or * is provided.
    :type if_match: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'if_match': {'key': 'If-Match', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        if_match: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsUpdateOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.if_match = if_match


class DigitalTwinsUpdateRelationshipOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param if_match: Only perform the operation if the entity's etag matches one of the etags
     provided or * is provided.
    :type if_match: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'if_match': {'key': 'If-Match', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        if_match: Optional[str] = None,
        **kwargs
    ):
        super(DigitalTwinsUpdateRelationshipOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.if_match = if_match


class Error(msrest.serialization.Model):
    """Error definition.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar code: Service specific error code which serves as the substatus for the HTTP error code.
    :vartype code: str
    :ivar message: A human-readable representation of the error.
    :vartype message: str
    :ivar details: Internal error details.
    :vartype details: list[~azure.digitaltwins.core.models.Error]
    :param innererror: An object containing more specific information than the current object about
     the error.
    :type innererror: ~azure.digitaltwins.core.models.InnerError
    """

    _validation = {
        'code': {'readonly': True},
        'message': {'readonly': True},
        'details': {'readonly': True},
    }

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': '[Error]'},
        'innererror': {'key': 'innererror', 'type': 'InnerError'},
    }

    def __init__(
        self,
        *,
        innererror: Optional["InnerError"] = None,
        **kwargs
    ):
        super(Error, self).__init__(**kwargs)
        self.code = None
        self.message = None
        self.details = None
        self.innererror = innererror


class ErrorResponse(msrest.serialization.Model):
    """Error response.

    :param error: The error details.
    :type error: ~azure.digitaltwins.core.models.Error
    """

    _attribute_map = {
        'error': {'key': 'error', 'type': 'Error'},
    }

    def __init__(
        self,
        *,
        error: Optional["Error"] = None,
        **kwargs
    ):
        super(ErrorResponse, self).__init__(**kwargs)
        self.error = error


class EventRouteCollection(msrest.serialization.Model):
    """A collection of EventRoute objects.

    :param value: The EventRoute objects.
    :type value: list[~azure.digitaltwins.core.models.DigitalTwinsEventRoute]
    :param next_link: A URI to retrieve the next page of results.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[DigitalTwinsEventRoute]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["DigitalTwinsEventRoute"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(EventRouteCollection, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class EventRoutesAddOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(EventRoutesAddOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class EventRoutesDeleteOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(EventRoutesDeleteOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class EventRoutesGetByIdOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        **kwargs
    ):
        super(EventRoutesGetByIdOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate


class EventRoutesListOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param max_items_per_page: The maximum number of items to retrieve per request. The server may
     choose to return less than the requested number.
    :type max_items_per_page: int
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'max_items_per_page': {'key': 'MaxItemsPerPage', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        max_items_per_page: Optional[int] = None,
        **kwargs
    ):
        super(EventRoutesListOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.max_items_per_page = max_items_per_page


class IncomingRelationship(msrest.serialization.Model):
    """An incoming relationship.

    :param relationship_id: A user-provided string representing the id of this relationship, unique
     in the context of the source digital twin, i.e. sourceId + relationshipId is unique in the
     context of the service.
    :type relationship_id: str
    :param source_id: The id of the source digital twin.
    :type source_id: str
    :param relationship_name: The name of the relationship.
    :type relationship_name: str
    :param relationship_link: Link to the relationship, to be used for deletion.
    :type relationship_link: str
    """

    _attribute_map = {
        'relationship_id': {'key': '$relationshipId', 'type': 'str'},
        'source_id': {'key': '$sourceId', 'type': 'str'},
        'relationship_name': {'key': '$relationshipName', 'type': 'str'},
        'relationship_link': {'key': '$relationshipLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        relationship_id: Optional[str] = None,
        source_id: Optional[str] = None,
        relationship_name: Optional[str] = None,
        relationship_link: Optional[str] = None,
        **kwargs
    ):
        super(IncomingRelationship, self).__init__(**kwargs)
        self.relationship_id = relationship_id
        self.source_id = source_id
        self.relationship_name = relationship_name
        self.relationship_link = relationship_link


class IncomingRelationshipCollection(msrest.serialization.Model):
    """A collection of incoming relationships which relate digital twins together.

    :param value:
    :type value: list[~azure.digitaltwins.core.models.IncomingRelationship]
    :param next_link: A URI to retrieve the next page of objects.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[IncomingRelationship]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["IncomingRelationship"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(IncomingRelationshipCollection, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class InnerError(msrest.serialization.Model):
    """A more specific error description than was provided by the containing error.

    :param code: A more specific error code than was provided by the containing error.
    :type code: str
    :param innererror: An object containing more specific information than the current object about
     the error.
    :type innererror: ~azure.digitaltwins.core.models.InnerError
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'innererror': {'key': 'innererror', 'type': 'InnerError'},
    }

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        innererror: Optional["InnerError"] = None,
        **kwargs
    ):
        super(InnerError, self).__init__(**kwargs)
        self.code = code
        self.innererror = innererror


class PagedDigitalTwinsModelDataCollection(msrest.serialization.Model):
    """A collection of DigitalTwinsModelData objects.

    :param value: The DigitalTwinsModelData objects.
    :type value: list[~azure.digitaltwins.core.models.DigitalTwinsModelData]
    :param next_link: A URI to retrieve the next page of objects.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[DigitalTwinsModelData]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["DigitalTwinsModelData"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(PagedDigitalTwinsModelDataCollection, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class QueryResult(msrest.serialization.Model):
    """The results of a query operation and an optional continuation token.

    :param value: The query results.
    :type value: list[object]
    :param continuation_token: A token which can be used to construct a new QuerySpecification to
     retrieve the next set of results.
    :type continuation_token: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[object]'},
        'continuation_token': {'key': 'continuationToken', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List[object]] = None,
        continuation_token: Optional[str] = None,
        **kwargs
    ):
        super(QueryResult, self).__init__(**kwargs)
        self.value = value
        self.continuation_token = continuation_token


class QuerySpecification(msrest.serialization.Model):
    """A query specification containing either a query statement or a continuation token from a previous query result.

    :param query: The query to execute. This value is ignored if a continuation token is provided.
    :type query: str
    :param continuation_token: A token which is used to retrieve the next set of results from a
     previous query.
    :type continuation_token: str
    """

    _attribute_map = {
        'query': {'key': 'query', 'type': 'str'},
        'continuation_token': {'key': 'continuationToken', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        query: Optional[str] = None,
        continuation_token: Optional[str] = None,
        **kwargs
    ):
        super(QuerySpecification, self).__init__(**kwargs)
        self.query = query
        self.continuation_token = continuation_token


class QueryTwinsOptions(msrest.serialization.Model):
    """Parameter group.

    :param traceparent: Identifies the request in a distributed tracing system.
    :type traceparent: str
    :param tracestate: Provides vendor-specific trace identification information and is a companion
     to traceparent.
    :type tracestate: str
    :param max_items_per_page: The maximum number of items to retrieve per request. The server may
     choose to return less than the requested number.
    :type max_items_per_page: int
    """

    _attribute_map = {
        'traceparent': {'key': 'traceparent', 'type': 'str'},
        'tracestate': {'key': 'tracestate', 'type': 'str'},
        'max_items_per_page': {'key': 'MaxItemsPerPage', 'type': 'int'},
    }

    def __init__(
        self,
        *,
        traceparent: Optional[str] = None,
        tracestate: Optional[str] = None,
        max_items_per_page: Optional[int] = None,
        **kwargs
    ):
        super(QueryTwinsOptions, self).__init__(**kwargs)
        self.traceparent = traceparent
        self.tracestate = tracestate
        self.max_items_per_page = max_items_per_page


class RelationshipCollection(msrest.serialization.Model):
    """A collection of relationships which relate digital twins together.

    :param value: The relationship objects.
    :type value: list[object]
    :param next_link: A URI to retrieve the next page of objects.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[object]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List[object]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(RelationshipCollection, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link
