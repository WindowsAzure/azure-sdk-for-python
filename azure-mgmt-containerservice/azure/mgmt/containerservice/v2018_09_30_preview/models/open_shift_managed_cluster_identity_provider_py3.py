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


class OpenShiftManagedClusterIdentityProvider(Model):
    """Defines the configuration of the identity providers to be used in the
    OpenShift cluster.

    :param name: Name of the provider.
    :type name: str
    :param provider: Configuration of the provider.
    :type provider:
     ~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftManagedClusterBaseIdentityProvider
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'OpenShiftManagedClusterBaseIdentityProvider'},
    }

    def __init__(self, *, name: str=None, provider=None, **kwargs) -> None:
        super(OpenShiftManagedClusterIdentityProvider, self).__init__(**kwargs)
        self.name = name
        self.provider = provider
