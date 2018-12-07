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

from .sub_resource import SubResource


class ApplicationGatewayUrlPathMap(SubResource):
    """UrlPathMaps give a url path to the backend mapping information for
    PathBasedRouting.

    :param id: Resource ID.
    :type id: str
    :param default_backend_address_pool: Default backend address pool resource
     of URL path map.
    :type default_backend_address_pool:
     ~azure.mgmt.network.v2018_06_01.models.SubResource
    :param default_backend_http_settings: Default backend http settings
     resource of URL path map.
    :type default_backend_http_settings:
     ~azure.mgmt.network.v2018_06_01.models.SubResource
    :param default_redirect_configuration: Default redirect configuration
     resource of URL path map.
    :type default_redirect_configuration:
     ~azure.mgmt.network.v2018_06_01.models.SubResource
    :param path_rules: Path rule of URL path map resource.
    :type path_rules:
     list[~azure.mgmt.network.v2018_06_01.models.ApplicationGatewayPathRule]
    :param provisioning_state: Provisioning state of the backend http settings
     resource. Possible values are: 'Updating', 'Deleting', and 'Failed'.
    :type provisioning_state: str
    :param name: Name of the URL path map that is unique within an Application
     Gateway.
    :type name: str
    :param etag: A unique read-only string that changes whenever the resource
     is updated.
    :type etag: str
    :param type: Type of the resource.
    :type type: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'default_backend_address_pool': {'key': 'properties.defaultBackendAddressPool', 'type': 'SubResource'},
        'default_backend_http_settings': {'key': 'properties.defaultBackendHttpSettings', 'type': 'SubResource'},
        'default_redirect_configuration': {'key': 'properties.defaultRedirectConfiguration', 'type': 'SubResource'},
        'path_rules': {'key': 'properties.pathRules', 'type': '[ApplicationGatewayPathRule]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ApplicationGatewayUrlPathMap, self).__init__(**kwargs)
        self.default_backend_address_pool = kwargs.get('default_backend_address_pool', None)
        self.default_backend_http_settings = kwargs.get('default_backend_http_settings', None)
        self.default_redirect_configuration = kwargs.get('default_redirect_configuration', None)
        self.path_rules = kwargs.get('path_rules', None)
        self.provisioning_state = kwargs.get('provisioning_state', None)
        self.name = kwargs.get('name', None)
        self.etag = kwargs.get('etag', None)
        self.type = kwargs.get('type', None)
