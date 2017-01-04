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


class RegisterApplicationType(Model):
    """The type of the register application.

    :param application_type_build_path:
    :type application_type_build_path: str
    """

    _attribute_map = {
        'application_type_build_path': {'key': 'ApplicationTypeBuildPath', 'type': 'str'},
    }

    def __init__(self, application_type_build_path=None):
        self.application_type_build_path = application_type_build_path
