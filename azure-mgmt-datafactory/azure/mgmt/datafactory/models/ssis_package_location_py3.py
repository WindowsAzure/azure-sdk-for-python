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


class SSISPackageLocation(Model):
    """SSIS package location.

    All required parameters must be populated in order to send to Azure.

    :param package_path: Required. The SSIS package path.
    :type package_path: str
    """

    _validation = {
        'package_path': {'required': True},
    }

    _attribute_map = {
        'package_path': {'key': 'packagePath', 'type': 'str'},
    }

    def __init__(self, *, package_path: str, **kwargs) -> None:
        super(SSISPackageLocation, self).__init__(**kwargs)
        self.package_path = package_path
