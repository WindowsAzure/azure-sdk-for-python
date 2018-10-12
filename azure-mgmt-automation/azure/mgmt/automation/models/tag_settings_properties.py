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


class TagSettingsProperties(Model):
    """Tag filter information of the VM.

    :param tags: dictionary of tags with its list of value
    :type tags: dict[str, list[str]]
    :param filter_operator: Possible values include: 'All', 'Any'
    :type filter_operator: str or ~azure.mgmt.automation.models.TagOperators
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{[str]}'},
        'filter_operator': {'key': 'filterOperator', 'type': 'TagOperators'},
    }

    def __init__(self, **kwargs):
        super(TagSettingsProperties, self).__init__(**kwargs)
        self.tags = kwargs.get('tags', None)
        self.filter_operator = kwargs.get('filter_operator', None)
