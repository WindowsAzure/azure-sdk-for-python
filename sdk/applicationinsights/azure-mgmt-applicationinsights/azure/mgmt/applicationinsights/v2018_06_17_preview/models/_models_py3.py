# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Dict, List, Optional, Union

from azure.core.exceptions import HttpResponseError
import msrest.serialization

from ._application_insights_management_client_enums import *


class ErrorFieldContract(msrest.serialization.Model):
    """Error Field contract.

    :param code: Property level error code.
    :type code: str
    :param message: Human-readable representation of property-level error.
    :type message: str
    :param target: Property name.
    :type target: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        message: Optional[str] = None,
        target: Optional[str] = None,
        **kwargs
    ):
        super(ErrorFieldContract, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.target = target


class Resource(msrest.serialization.Model):
    """An azure resource object.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name. This is GUID value. The display name should be assigned within
     properties field.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param kind: The kind of workbook. Choices are user and shared. Possible values include:
     "user", "shared".
    :type kind: str or ~azure.mgmt.applicationinsights.v2018_06_17_preview.models.SharedTypeKind
    :param location: Required. Resource location.
    :type location: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        *,
        location: str,
        kind: Optional[Union[str, "SharedTypeKind"]] = None,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(Resource, self).__init__(**kwargs)
        self.id = None
        self.name = None
        self.type = None
        self.kind = kind
        self.location = location
        self.tags = tags


class Workbook(Resource):
    """An Application Insights workbook definition.

    Variables are only populated by the server, and will be ignored when sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id.
    :vartype id: str
    :ivar name: Azure resource name. This is GUID value. The display name should be assigned within
     properties field.
    :vartype name: str
    :ivar type: Azure resource type.
    :vartype type: str
    :param kind: The kind of workbook. Choices are user and shared. Possible values include:
     "user", "shared".
    :type kind: str or ~azure.mgmt.applicationinsights.v2018_06_17_preview.models.SharedTypeKind
    :param location: Required. Resource location.
    :type location: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param display_name: The user-defined name (display name) of the workbook.
    :type display_name: str
    :param serialized_data: Configuration of this particular workbook. Configuration data is a
     string containing valid JSON.
    :type serialized_data: str
    :ivar time_modified: Date and time in UTC of the last modification that was made to this
     workbook definition.
    :vartype time_modified: str
    :param category: Workbook category, as defined by the user at creation time.
    :type category: str
    :param version: Workbook version.
    :type version: str
    :param tags_properties_tags: A list of 0 or more tags that are associated with this workbook
     definition.
    :type tags_properties_tags: list[str]
    :ivar user_id: Unique user id of the specific user that owns this workbook.
    :vartype user_id: str
    :param source_id: ResourceId for a source resource.
    :type source_id: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'time_modified': {'readonly': True},
        'user_id': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'serialized_data': {'key': 'properties.serializedData', 'type': 'str'},
        'time_modified': {'key': 'properties.timeModified', 'type': 'str'},
        'category': {'key': 'properties.category', 'type': 'str'},
        'version': {'key': 'properties.version', 'type': 'str'},
        'tags_properties_tags': {'key': 'properties.tags', 'type': '[str]'},
        'user_id': {'key': 'properties.userId', 'type': 'str'},
        'source_id': {'key': 'properties.sourceId', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        location: str,
        kind: Optional[Union[str, "SharedTypeKind"]] = None,
        tags: Optional[Dict[str, str]] = None,
        display_name: Optional[str] = None,
        serialized_data: Optional[str] = None,
        category: Optional[str] = None,
        version: Optional[str] = None,
        tags_properties_tags: Optional[List[str]] = None,
        source_id: Optional[str] = None,
        **kwargs
    ):
        super(Workbook, self).__init__(kind=kind, location=location, tags=tags, **kwargs)
        self.display_name = display_name
        self.serialized_data = serialized_data
        self.time_modified = None
        self.category = category
        self.version = version
        self.tags_properties_tags = tags_properties_tags
        self.user_id = None
        self.source_id = source_id


class WorkbookError(msrest.serialization.Model):
    """Error message body that will indicate why the operation failed.

    :param code: Service-defined error code. This code serves as a sub-status for the HTTP error
     code specified in the response.
    :type code: str
    :param message: Human-readable representation of the error.
    :type message: str
    :param details: The list of invalid fields send in request, in case of validation error.
    :type details:
     list[~azure.mgmt.applicationinsights.v2018_06_17_preview.models.ErrorFieldContract]
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorFieldContract]'},
    }

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        message: Optional[str] = None,
        details: Optional[List["ErrorFieldContract"]] = None,
        **kwargs
    ):
        super(WorkbookError, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.details = details


class WorkbooksListResult(msrest.serialization.Model):
    """Workbook list result.

    :param value: An array of workbooks.
    :type value: list[~azure.mgmt.applicationinsights.v2018_06_17_preview.models.Workbook]
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[Workbook]'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["Workbook"]] = None,
        **kwargs
    ):
        super(WorkbooksListResult, self).__init__(**kwargs)
        self.value = value


class WorkbookUpdateParameters(msrest.serialization.Model):
    """The parameters that can be provided when updating workbook properties properties.

    :param kind: The kind of workbook. Choices are user and shared. Possible values include:
     "user", "shared".
    :type kind: str or ~azure.mgmt.applicationinsights.v2018_06_17_preview.models.SharedTypeKind
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :param display_name: The user-defined name (display name) of the workbook.
    :type display_name: str
    :param serialized_data: Configuration of this particular workbook. Configuration data is a
     string containing valid JSON.
    :type serialized_data: str
    :param category: Workbook category, as defined by the user at creation time.
    :type category: str
    :param tags_properties_tags: A list of 0 or more tags that are associated with this workbook
     definition.
    :type tags_properties_tags: list[str]
    """

    _attribute_map = {
        'kind': {'key': 'kind', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'display_name': {'key': 'properties.displayName', 'type': 'str'},
        'serialized_data': {'key': 'properties.serializedData', 'type': 'str'},
        'category': {'key': 'properties.category', 'type': 'str'},
        'tags_properties_tags': {'key': 'properties.tags', 'type': '[str]'},
    }

    def __init__(
        self,
        *,
        kind: Optional[Union[str, "SharedTypeKind"]] = None,
        tags: Optional[Dict[str, str]] = None,
        display_name: Optional[str] = None,
        serialized_data: Optional[str] = None,
        category: Optional[str] = None,
        tags_properties_tags: Optional[List[str]] = None,
        **kwargs
    ):
        super(WorkbookUpdateParameters, self).__init__(**kwargs)
        self.kind = kind
        self.tags = tags
        self.display_name = display_name
        self.serialized_data = serialized_data
        self.category = category
        self.tags_properties_tags = tags_properties_tags
