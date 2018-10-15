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


class GlobalServiceConfiguration(Model):
    """Global configuration for services in the cluster.

    :param additional_properties: Unmatched properties from the message are
     deserialized this collection
    :type additional_properties: dict[str, object]
    :param etag: The configuartion ETag for updates.
    :type etag: str
    :param ssl: The SSL configuration properties
    :type ssl: ~azure.mgmt.machinelearningcompute.models.SslConfiguration
    :param service_auth: Optional global authorization keys for all user
     services deployed in cluster. These are used if the service does not have
     auth keys.
    :type service_auth:
     ~azure.mgmt.machinelearningcompute.models.ServiceAuthConfiguration
    :param auto_scale: The auto-scale configuration
    :type auto_scale:
     ~azure.mgmt.machinelearningcompute.models.AutoScaleConfiguration
    """

    _attribute_map = {
        'additional_properties': {'key': '', 'type': '{object}'},
        'etag': {'key': 'etag', 'type': 'str'},
        'ssl': {'key': 'ssl', 'type': 'SslConfiguration'},
        'service_auth': {'key': 'serviceAuth', 'type': 'ServiceAuthConfiguration'},
        'auto_scale': {'key': 'autoScale', 'type': 'AutoScaleConfiguration'},
    }

    def __init__(self, *, additional_properties=None, etag: str=None, ssl=None, service_auth=None, auto_scale=None, **kwargs) -> None:
        super(GlobalServiceConfiguration, self).__init__(**kwargs)
        self.additional_properties = additional_properties
        self.etag = etag
        self.ssl = ssl
        self.service_auth = service_auth
        self.auto_scale = auto_scale
