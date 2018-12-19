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


class OpenShiftManagedClusterAuthProfile(Model):
    """Defines all possible authentication profiles for the OpenShift cluster.

    :param identity_providers: Type of authentication profile to use.
    :type identity_providers:
     list[~azure.mgmt.containerservice.v2018_09_30_preview.models.OpenShiftManagedClusterIdentityProvider]
    """

    _attribute_map = {
        'identity_providers': {'key': 'identityProviders', 'type': '[OpenShiftManagedClusterIdentityProvider]'},
    }

    def __init__(self, *, identity_providers=None, **kwargs) -> None:
        super(OpenShiftManagedClusterAuthProfile, self).__init__(**kwargs)
        self.identity_providers = identity_providers
