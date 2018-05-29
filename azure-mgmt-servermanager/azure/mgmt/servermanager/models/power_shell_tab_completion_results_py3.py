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


class PowerShellTabCompletionResults(Model):
    """An array of strings representing the different values that can be selected
    through.

    :param results:
    :type results: list[str]
    """

    _attribute_map = {
        'results': {'key': 'results', 'type': '[str]'},
    }

    def __init__(self, *, results=None, **kwargs) -> None:
        super(PowerShellTabCompletionResults, self).__init__(**kwargs)
        self.results = results
