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


class FactoryRepoUpdate(Model):
    """Factory's git repo information.

    :param factory_resource_id: The factory resource id.
    :type factory_resource_id: str
    :param repo_configuration: Git repo information of the factory.
    :type repo_configuration:
     ~azure.mgmt.datafactory.models.FactoryRepoConfiguration
    """

    _attribute_map = {
        'factory_resource_id': {'key': 'factoryResourceId', 'type': 'str'},
        'repo_configuration': {'key': 'repoConfiguration', 'type': 'FactoryRepoConfiguration'},
    }

    def __init__(self, *, factory_resource_id: str=None, repo_configuration=None, **kwargs) -> None:
        super(FactoryRepoUpdate, self).__init__(**kwargs)
        self.factory_resource_id = factory_resource_id
        self.repo_configuration = repo_configuration
