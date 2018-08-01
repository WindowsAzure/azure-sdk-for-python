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


class ValidateRequest(Model):
    """Resource validation request content.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. Resource name to verify.
    :type name: str
    :param type: Required. Resource type used for verification. Possible
     values include: 'ServerFarm', 'Site'
    :type type: str or ~azure.mgmt.web.models.ValidateResourceTypes
    :param location: Required. Expected location of the resource.
    :type location: str
    :param server_farm_id: ARM resource ID of an App Service plan that would
     host the app.
    :type server_farm_id: str
    :param sku_name: Name of the target SKU for the App Service plan.
    :type sku_name: str
    :param need_linux_workers: <code>true</code> if App Service plan is for
     Linux workers; otherwise, <code>false</code>.
    :type need_linux_workers: bool
    :param is_spot: <code>true</code> if App Service plan is for Spot
     instances; otherwise, <code>false</code>.
    :type is_spot: bool
    :param capacity: Target capacity of the App Service plan (number of VM's).
    :type capacity: int
    :param hosting_environment: Name of App Service Environment where app or
     App Service plan should be created.
    :type hosting_environment: str
    :param is_xenon: <code>true</code> if App Service plan is running as a
     windows container
    :type is_xenon: bool
    """

    _validation = {
        'name': {'required': True},
        'type': {'required': True},
        'location': {'required': True},
        'capacity': {'minimum': 1},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'server_farm_id': {'key': 'properties.serverFarmId', 'type': 'str'},
        'sku_name': {'key': 'properties.skuName', 'type': 'str'},
        'need_linux_workers': {'key': 'properties.needLinuxWorkers', 'type': 'bool'},
        'is_spot': {'key': 'properties.isSpot', 'type': 'bool'},
        'capacity': {'key': 'properties.capacity', 'type': 'int'},
        'hosting_environment': {'key': 'properties.hostingEnvironment', 'type': 'str'},
        'is_xenon': {'key': 'properties.isXenon', 'type': 'bool'},
    }

    def __init__(self, *, name: str, type, location: str, server_farm_id: str=None, sku_name: str=None, need_linux_workers: bool=None, is_spot: bool=None, capacity: int=None, hosting_environment: str=None, is_xenon: bool=None, **kwargs) -> None:
        super(ValidateRequest, self).__init__(**kwargs)
        self.name = name
        self.type = type
        self.location = location
        self.server_farm_id = server_farm_id
        self.sku_name = sku_name
        self.need_linux_workers = need_linux_workers
        self.is_spot = is_spot
        self.capacity = capacity
        self.hosting_environment = hosting_environment
        self.is_xenon = is_xenon
