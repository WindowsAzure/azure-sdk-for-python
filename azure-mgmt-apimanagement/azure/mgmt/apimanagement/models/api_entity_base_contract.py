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


class ApiEntityBaseContract(Model):
    """API base contract details.

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
    :ivar is_current: Indicates if API revision is current api revision.
    :vartype is_current: bool
    :ivar is_online: Indicates if API revision is accessible via the gateway.
    :vartype is_online: bool
    :param api_revision_description: Description of the Api Revision.
    :type api_revision_description: str
    :param api_version_description: Description of the Api Version.
    :type api_version_description: str
    :param api_version_set_id: A resource identifier for the related
     ApiVersionSet.
    :type api_version_set_id: str
    """

    _validation = {
        'api_revision': {'max_length': 100, 'min_length': 1},
        'api_version': {'max_length': 100},
        'is_current': {'readonly': True},
        'is_online': {'readonly': True},
        'api_revision_description': {'max_length': 256},
        'api_version_description': {'max_length': 256},
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
    }

    def __init__(self, **kwargs):
        super(ApiEntityBaseContract, self).__init__(**kwargs)
        self.description = kwargs.get('description', None)
        self.authentication_settings = kwargs.get('authentication_settings', None)
        self.subscription_key_parameter_names = kwargs.get('subscription_key_parameter_names', None)
        self.api_type = kwargs.get('api_type', None)
        self.api_revision = kwargs.get('api_revision', None)
        self.api_version = kwargs.get('api_version', None)
        self.is_current = None
        self.is_online = None
        self.api_revision_description = kwargs.get('api_revision_description', None)
        self.api_version_description = kwargs.get('api_version_description', None)
        self.api_version_set_id = kwargs.get('api_version_set_id', None)
