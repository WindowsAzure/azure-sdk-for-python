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

from msrest.serialization import Model


class NamespaceProperties(Model):
    """
    Namespace properties.

    :param name: The name of the namespace.
    :type name: str
    :param provisioning_state: Gets or sets provisioning state of the
     Namespace.
    :type provisioning_state: str
    :param region: Specifies the targeted region in which the namespace
     should be created. It can be any of the following values: Australia
     EastAustralia SoutheastCentral USEast USEast US 2West USNorth Central
     USSouth Central USEast AsiaSoutheast AsiaBrazil SouthJapan EastJapan
     WestNorth EuropeWest Europe
    :type region: str
    :param status: Status of the namespace. It can be any of these values:1 =
     Created/Active2 = Creating3 = Suspended4 = Deleting
    :type status: str
    :param created_at: The time the namespace was created.
    :type created_at: datetime
    :param service_bus_endpoint: Endpoint you can use to perform
     NotificationHub operations.
    :type service_bus_endpoint: str
    :param subscription_id: The Id of the Azure subscription associated with
     the namespace.
    :type subscription_id: str
    :param scale_unit: ScaleUnit where the namespace gets created
    :type scale_unit: str
    :param enabled: Whether or not the namespace is currently enabled.
    :type enabled: bool
    :param critical: Whether or not the namespace is set as Critical.
    :type critical: bool
    :param namespace_type: Gets or sets the namespace type. Possible values
     include: 'Messaging', 'NotificationHub'
    :type namespace_type: str or :class:`NamespaceType
     <notificationhubsmanagementclient.models.NamespaceType>`
    """ 

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'provisioning_state': {'key': 'provisioningState', 'type': 'str'},
        'region': {'key': 'region', 'type': 'str'},
        'status': {'key': 'status', 'type': 'str'},
        'created_at': {'key': 'createdAt', 'type': 'iso-8601'},
        'service_bus_endpoint': {'key': 'serviceBusEndpoint', 'type': 'str'},
        'subscription_id': {'key': 'subscriptionId', 'type': 'str'},
        'scale_unit': {'key': 'scaleUnit', 'type': 'str'},
        'enabled': {'key': 'enabled', 'type': 'bool'},
        'critical': {'key': 'critical', 'type': 'bool'},
        'namespace_type': {'key': 'namespaceType', 'type': 'NamespaceType'},
    }

    def __init__(self, name=None, provisioning_state=None, region=None, status=None, created_at=None, service_bus_endpoint=None, subscription_id=None, scale_unit=None, enabled=None, critical=None, namespace_type=None):
        self.name = name
        self.provisioning_state = provisioning_state
        self.region = region
        self.status = status
        self.created_at = created_at
        self.service_bus_endpoint = service_bus_endpoint
        self.subscription_id = subscription_id
        self.scale_unit = scale_unit
        self.enabled = enabled
        self.critical = critical
        self.namespace_type = namespace_type
