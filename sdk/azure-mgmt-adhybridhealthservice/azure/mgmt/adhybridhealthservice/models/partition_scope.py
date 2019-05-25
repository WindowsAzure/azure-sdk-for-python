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


class PartitionScope(Model):
    """The connector partition scope.

    :param is_default: Indicates if the partition scope is default or not.
    :type is_default: bool
    :param object_classes: The in-scope object classes.
    :type object_classes: list[str]
    :param containers_included: The list of containers included.
    :type containers_included: list[str]
    :param containers_excluded: The list of containers excluded.
    :type containers_excluded: list[str]
    """

    _attribute_map = {
        'is_default': {'key': 'isDefault', 'type': 'bool'},
        'object_classes': {'key': 'objectClasses', 'type': '[str]'},
        'containers_included': {'key': 'containersIncluded', 'type': '[str]'},
        'containers_excluded': {'key': 'containersExcluded', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(PartitionScope, self).__init__(**kwargs)
        self.is_default = kwargs.get('is_default', None)
        self.object_classes = kwargs.get('object_classes', None)
        self.containers_included = kwargs.get('containers_included', None)
        self.containers_excluded = kwargs.get('containers_excluded', None)
