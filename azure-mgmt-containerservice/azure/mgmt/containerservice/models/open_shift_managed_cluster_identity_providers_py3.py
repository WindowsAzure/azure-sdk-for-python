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


class OpenShiftManagedClusterIdentityProviders(Model):
    """OpenShiftManagedClusterIdentityProvider is heavily cut down equivalent to
    IdentityProvider in the upstream.

    :param name: Name of the provider.
    :type name: str
    :param provider: Configuration of the provider.
    :type provider: object
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'provider': {'key': 'provider', 'type': 'object'},
    }

    def __init__(self, *, name: str=None, provider=None, **kwargs) -> None:
        super(OpenShiftManagedClusterIdentityProviders, self).__init__(**kwargs)
        self.name = name
        self.provider = provider
