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


class OpenShiftRouterProfile(Model):
    """Represents an OpenShift router.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param name: Name of the router profile.
    :type name: str
    :ivar public_subdomain: DNS subdomain for OpenShift router.
    :vartype public_subdomain: str
    :ivar fqdn: Auto-allocated FQDN for the OpenShift router.
    :vartype fqdn: str
    """

    _validation = {
        'public_subdomain': {'readonly': True},
        'fqdn': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'public_subdomain': {'key': 'publicSubdomain', 'type': 'str'},
        'fqdn': {'key': 'fqdn', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, **kwargs) -> None:
        super(OpenShiftRouterProfile, self).__init__(**kwargs)
        self.name = name
        self.public_subdomain = None
        self.fqdn = None
