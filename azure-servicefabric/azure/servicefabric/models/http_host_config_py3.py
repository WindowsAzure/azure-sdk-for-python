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


class HttpHostConfig(Model):
    """Describes the hostname properties for http routing.

    All required parameters must be populated in order to send to Azure.

    :param name: Required. http hostname config name.
    :type name: str
    :param routes: Required. Route information to use for routing. Routes are
     processed in the order they are specified. Specify routes that are more
     specific before routes that can hamdle general cases.
    :type routes: list[~azure.servicefabric.models.HttpRouteConfig]
    """

    _validation = {
        'name': {'required': True},
        'routes': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'routes': {'key': 'routes', 'type': '[HttpRouteConfig]'},
    }

    def __init__(self, *, name: str, routes, **kwargs) -> None:
        super(HttpHostConfig, self).__init__(**kwargs)
        self.name = name
        self.routes = routes
