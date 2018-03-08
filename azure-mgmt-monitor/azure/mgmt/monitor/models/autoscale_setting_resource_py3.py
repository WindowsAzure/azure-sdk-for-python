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

from .resource import Resource


class AutoscaleSettingResource(Resource):
    """The autoscale setting resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param location: Required. Resource location
    :type location: str
    :param tags: Resource tags
    :type tags: dict[str, str]
    :param profiles: Required. the collection of automatic scaling profiles
     that specify different scaling parameters for different time periods. A
     maximum of 20 profiles can be specified.
    :type profiles: list[~azure.mgmt.monitor.models.AutoscaleProfile]
    :param notifications: the collection of notifications.
    :type notifications:
     list[~azure.mgmt.monitor.models.AutoscaleNotification]
    :param enabled: the enabled flag. Specifies whether automatic scaling is
     enabled for the resource. The default value is 'true'. Default value: True
     .
    :type enabled: bool
    :param autoscale_setting_resource_name: the name of the autoscale setting.
    :type autoscale_setting_resource_name: str
    :param target_resource_uri: the resource identifier of the resource that
     the autoscale setting should be added to.
    :type target_resource_uri: str
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'location': {'required': True},
        'profiles': {'required': True, 'max_items': 20},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'profiles': {'key': 'properties.profiles', 'type': '[AutoscaleProfile]'},
        'notifications': {'key': 'properties.notifications', 'type': '[AutoscaleNotification]'},
        'enabled': {'key': 'properties.enabled', 'type': 'bool'},
        'autoscale_setting_resource_name': {'key': 'properties.name', 'type': 'str'},
        'target_resource_uri': {'key': 'properties.targetResourceUri', 'type': 'str'},
    }

    def __init__(self, *, location: str, profiles, tags=None, notifications=None, enabled: bool=True, autoscale_setting_resource_name: str=None, target_resource_uri: str=None, **kwargs) -> None:
        super(AutoscaleSettingResource, self).__init__(location=location, tags=tags, **kwargs)
        self.profiles = profiles
        self.notifications = notifications
        self.enabled = enabled
        self.autoscale_setting_resource_name = autoscale_setting_resource_name
        self.target_resource_uri = target_resource_uri
