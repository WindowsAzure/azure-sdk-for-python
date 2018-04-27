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


class HostingEnvironmentDiagnostics(Model):
    """Diagnostics for an App Service Environment.

    :param name: Name/identifier of the diagnostics.
    :type name: str
    :param diagnosics_output: Diagnostics output.
    :type diagnosics_output: str
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'diagnosics_output': {'key': 'diagnosicsOutput', 'type': 'str'},
    }

    def __init__(self, *, name: str=None, diagnosics_output: str=None, **kwargs) -> None:
        super(HostingEnvironmentDiagnostics, self).__init__(**kwargs)
        self.name = name
        self.diagnosics_output = diagnosics_output
