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


class FabricCodeVersionInfo(Model):
    """Information about a Service Fabric code version.

    :param code_version: The product version of Service Fabric.
    :type code_version: str
    """

    _attribute_map = {
        'code_version': {'key': 'CodeVersion', 'type': 'str'},
    }

    def __init__(self, *, code_version: str=None, **kwargs) -> None:
        super(FabricCodeVersionInfo, self).__init__(**kwargs)
        self.code_version = code_version
