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

from .api_entity_base_contract_py3 import ApiEntityBaseContract


class ApiTagResourceContractProperties(ApiEntityBaseContract):
    """API contract properties for the Tag Resources.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param description: Description of the API. May include HTML formatting
     tags.
    :type description: str
    :param authentication_settings: Collection of authentication settings
     included into this API.
    :type authentication_settings:
     ~azure.mgmt.apimanagement.models.AuthenticationSettingsContract
    :param subscription_key_parameter_names: Protocols over which API is made
     available.
    :type subscription_key_parameter_names:
     ~azure.mgmt.apimanagement.models.SubscriptionKeyParameterNamesContract
    :param api_type: Type of API. Possible values include: 'http', 'soap'
    :type api_type: str or ~azure.mgmt.apimanagement.models.ApiType
    :param api_revision: Describes the Revision of the Api. If no value is
     provided, default revision 1 is created
    :type api_revision: str
    :param api_version: Indicates the Version identifier of the API if the API
     is versioned
    :type api_version: str
    :param is_current: Indicates if API revision is current api revision.
    :type is_current: bool
    :ivar is_online: Indicates if API revision is accessible via the gateway.
    :vartype is_online: bool
    :param api_revision_description: Description of the Api Revision.
    :type api_revision_description: str
    :param api_version_description: Description of the Api Version.
    :type api_version_description: str
    :param api_version_set_id: A resource identifier for the related
     ApiVersionSet.
    :type api_version_set_id: str
    :param subscription_required: Specifies whether an API or Product
     subscription is required for accessing the API.
    :type subscription_required: bool
    :param id: API identifier in the form /apis/{apiId}.
    :type id: str
    :param name: API name.
    :type name: str
    :param service_url: Absolute URL of the backend service implementing this
     API.
    :type service_url: str
    :param path: Relative URL uniquely identifying this API and all of its
     resource paths within the API Management service instance. It is appended
     to the API endpoint base URL specified during the service instance
     creation to form a public URL for this API.
    :type path: str
    :param protocols: Describes on which protocols the operations in this API
     can be invoked.
    :type protocols: list[str or ~azure.mgmt.apimanagement.models.Protocol]
    """

    _validation = {
        'api_revision': {'max_length': 100, 'min_length': 1},
        'api_version': {'max_length': 100},
        'is_online': {'readonly': True},
        'api_revision_description': {'max_length': 256},
        'api_version_description': {'max_length': 256},
        'name': {'max_length': 300, 'min_length': 1},
        'service_url': {'max_length': 2000, 'min_length': 1},
        'path': {'max_length': 400, 'min_length': 0},
    }

    _attribute_map = {
        'description': {'key': 'description', 'type': 'str'},
        'authentication_settings': {'key': 'authenticationSettings', 'type': 'AuthenticationSettingsContract'},
        'subscription_key_parameter_names': {'key': 'subscriptionKeyParameterNames', 'type': 'SubscriptionKeyParameterNamesContract'},
        'api_type': {'key': 'type', 'type': 'str'},
        'api_revision': {'key': 'apiRevision', 'type': 'str'},
        'api_version': {'key': 'apiVersion', 'type': 'str'},
        'is_current': {'key': 'isCurrent', 'type': 'bool'},
        'is_online': {'key': 'isOnline', 'type': 'bool'},
        'api_revision_description': {'key': 'apiRevisionDescription', 'type': 'str'},
        'api_version_description': {'key': 'apiVersionDescription', 'type': 'str'},
        'api_version_set_id': {'key': 'apiVersionSetId', 'type': 'str'},
        'subscription_required': {'key': 'subscriptionRequired', 'type': 'bool'},
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'service_url': {'key': 'serviceUrl', 'type': 'str'},
        'path': {'key': 'path', 'type': 'str'},
        'protocols': {'key': 'protocols', 'type': '[Protocol]'},
    }

    def __init__(self, *, description: str=None, authentication_settings=None, subscription_key_parameter_names=None, api_type=None, api_revision: str=None, api_version: str=None, is_current: bool=None, api_revision_description: str=None, api_version_description: str=None, api_version_set_id: str=None, subscription_required: bool=None, id: str=None, name: str=None, service_url: str=None, path: str=None, protocols=None, **kwargs) -> None:
        super(ApiTagResourceContractProperties, self).__init__(description=description, authentication_settings=authentication_settings, subscription_key_parameter_names=subscription_key_parameter_names, api_type=api_type, api_revision=api_revision, api_version=api_version, is_current=is_current, api_revision_description=api_revision_description, api_version_description=api_version_description, api_version_set_id=api_version_set_id, subscription_required=subscription_required, **kwargs)
        self.id = id
        self.name = name
        self.service_url = service_url
        self.path = path
        self.protocols = protocols
