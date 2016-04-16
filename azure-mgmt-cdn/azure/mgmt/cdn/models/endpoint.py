# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft and contributors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .tracked_resource import TrackedResource


class Endpoint(TrackedResource):
    """
    CDN endpoint is the entity within a CDN profile containing configuration
    information regarding caching behaviors and origins. The CDN endpoint is
    exposed using the URL format <endpointname>.azureedge.net by default, but
    custom domains can also be created.

    :param id: Resource ID
    :type id: str
    :param name: Resource name
    :type name: str
    :param type: Resource type
    :type type: str
    :param location: Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict
    :param host_name: The host name of the endpoint {endpointName}.{DNSZone}
    :type host_name: str
    :param origin_host_header: The host header the CDN provider will send
     along with content requests to origins. The default value is the host
     name of the origin.
    :type origin_host_header: str
    :param origin_path: The path used for origin requests.
    :type origin_path: str
    :param content_types_to_compress: List of content types on which
     compression will be applied. The value for the elements should be a
     valid MIME type.
    :type content_types_to_compress: list of str
    :param is_compression_enabled: Indicates whether the compression is
     enabled. Default value is false. If compression is enabled, the content
     transferred from cdn endpoint to end user will be compressed. The
     requested content must be larger than 1 byte and smaller than 1 MB.
    :type is_compression_enabled: bool
    :param is_http_allowed: Indicates whether HTTP traffic is allowed on the
     endpoint. Default value is true. At least one protocol (HTTP or HTTPS)
     must be allowed.
    :type is_http_allowed: bool
    :param is_https_allowed: Indicates whether https traffic is allowed on
     the endpoint. Default value is true. At least one protocol (HTTP or
     HTTPS) must be allowed.
    :type is_https_allowed: bool
    :param query_string_caching_behavior: Defines the query string caching
     behavior. Possible values include: 'IgnoreQueryString', 'BypassCaching',
     'UseQueryString', 'NotSet'
    :type query_string_caching_behavior: str
    :param origins: The set of origins for the CDN endpoint. When multiple
     origins exist, the first origin will be used as primary and rest will be
     used as failover options.
    :type origins: list of :class:`DeepCreatedOrigin
     <cdnmanagementclient.models.DeepCreatedOrigin>`
    :param resource_state: Resource status of the endpoint. Possible values
     include: 'Creating', 'Deleting', 'Running', 'Starting', 'Stopped',
     'Stopping'
    :type resource_state: str
    :param provisioning_state: Provisioning status of the endpoint. Possible
     values include: 'Creating', 'Succeeded', 'Failed'
    :type provisioning_state: str
    """ 

    _validation = {
        'location': {'required': True},
        'tags': {'required': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'host_name': {'key': 'properties.hostName', 'type': 'str'},
        'origin_host_header': {'key': 'properties.originHostHeader', 'type': 'str'},
        'origin_path': {'key': 'properties.originPath', 'type': 'str'},
        'content_types_to_compress': {'key': 'properties.contentTypesToCompress', 'type': '[str]'},
        'is_compression_enabled': {'key': 'properties.isCompressionEnabled', 'type': 'bool'},
        'is_http_allowed': {'key': 'properties.isHttpAllowed', 'type': 'bool'},
        'is_https_allowed': {'key': 'properties.isHttpsAllowed', 'type': 'bool'},
        'query_string_caching_behavior': {'key': 'properties.queryStringCachingBehavior', 'type': 'QueryStringCachingBehavior'},
        'origins': {'key': 'properties.origins', 'type': '[DeepCreatedOrigin]'},
        'resource_state': {'key': 'properties.resourceState', 'type': 'EndpointResourceState'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'ProvisioningState'},
    }

    def __init__(self, location, tags, id=None, name=None, type=None, host_name=None, origin_host_header=None, origin_path=None, content_types_to_compress=None, is_compression_enabled=None, is_http_allowed=None, is_https_allowed=None, query_string_caching_behavior=None, origins=None, resource_state=None, provisioning_state=None):
        super(Endpoint, self).__init__(id=id, name=name, type=type, location=location, tags=tags)
        self.host_name = host_name
        self.origin_host_header = origin_host_header
        self.origin_path = origin_path
        self.content_types_to_compress = content_types_to_compress
        self.is_compression_enabled = is_compression_enabled
        self.is_http_allowed = is_http_allowed
        self.is_https_allowed = is_https_allowed
        self.query_string_caching_behavior = query_string_caching_behavior
        self.origins = origins
        self.resource_state = resource_state
        self.provisioning_state = provisioning_state
