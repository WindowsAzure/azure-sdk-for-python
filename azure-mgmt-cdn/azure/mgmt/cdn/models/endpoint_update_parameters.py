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


class EndpointUpdateParameters(Model):
    """Properties required to create a new endpoint.

    :param tags: Endpoint tags.
    :type tags: dict
    :param origin_host_header: The host header CDN sends along with content
     requests to origin. The default value is the host name of the origin.
    :type origin_host_header: str
    :param origin_path: The path used when CDN sends request to origin.
    :type origin_path: str
    :param content_types_to_compress: List of content types on which
     compression applies. The value should be a valid MIME type.
    :type content_types_to_compress: list of str
    :param is_compression_enabled: Indicates whether content compression is
     enabled on CDN. Default value is false. If compression is enabled, content
     will be served as compressed if user requests for a compressed version.
     Content won't be compressed on CDN when requested content is smaller than
     1 byte or larger than 1 MB.
    :type is_compression_enabled: bool
    :param is_http_allowed: Indicates whether HTTP traffic is allowed on the
     endpoint. Default value is true. At least one protocol (HTTP or HTTPS)
     must be allowed.
    :type is_http_allowed: bool
    :param is_https_allowed: Indicates whether HTTPS traffic is allowed on the
     endpoint. Default value is true. At least one protocol (HTTP or HTTPS)
     must be allowed.
    :type is_https_allowed: bool
    :param query_string_caching_behavior: Defines the query string caching
     behavior. Possible values include: 'IgnoreQueryString', 'BypassCaching',
     'UseQueryString', 'NotSet'
    :type query_string_caching_behavior: str or
     :class:`QueryStringCachingBehavior
     <azure.mgmt.cdn.models.QueryStringCachingBehavior>`
    :param optimization_type: Customer can specify what scenario they want
     this CDN endpoint to optimize, e.g. Download, Media services. With this
     information we can apply scenario driven optimization. Possible values
     include: 'GeneralWebDelivery', 'GeneralMediaStreaming',
     'VideoOnDemandMediaStreaming', 'LargeFileDownload',
     'DynamicSiteAcceleration'
    :type optimization_type: str or :class:`OptimizationType
     <azure.mgmt.cdn.models.OptimizationType>`
    :param geo_filters: List of rules defining user geo access within a CDN
     endpoint. Each geo filter defines an acess rule to a specified path or
     content, e.g. block APAC for path /pictures/
    :type geo_filters: list of :class:`GeoFilter
     <azure.mgmt.cdn.models.GeoFilter>`
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
        'origin_host_header': {'key': 'properties.originHostHeader', 'type': 'str'},
        'origin_path': {'key': 'properties.originPath', 'type': 'str'},
        'content_types_to_compress': {'key': 'properties.contentTypesToCompress', 'type': '[str]'},
        'is_compression_enabled': {'key': 'properties.isCompressionEnabled', 'type': 'bool'},
        'is_http_allowed': {'key': 'properties.isHttpAllowed', 'type': 'bool'},
        'is_https_allowed': {'key': 'properties.isHttpsAllowed', 'type': 'bool'},
        'query_string_caching_behavior': {'key': 'properties.queryStringCachingBehavior', 'type': 'QueryStringCachingBehavior'},
        'optimization_type': {'key': 'properties.optimizationType', 'type': 'str'},
        'geo_filters': {'key': 'properties.geoFilters', 'type': '[GeoFilter]'},
    }

    def __init__(self, tags=None, origin_host_header=None, origin_path=None, content_types_to_compress=None, is_compression_enabled=None, is_http_allowed=None, is_https_allowed=None, query_string_caching_behavior=None, optimization_type=None, geo_filters=None):
        self.tags = tags
        self.origin_host_header = origin_host_header
        self.origin_path = origin_path
        self.content_types_to_compress = content_types_to_compress
        self.is_compression_enabled = is_compression_enabled
        self.is_http_allowed = is_http_allowed
        self.is_https_allowed = is_https_allowed
        self.query_string_caching_behavior = query_string_caching_behavior
        self.optimization_type = optimization_type
        self.geo_filters = geo_filters
