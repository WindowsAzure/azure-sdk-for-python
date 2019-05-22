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


class DateAfterCreation(Model):
    """Object to define the number of days after creation.

    All required parameters must be populated in order to send to Azure.

    :param days_after_creation_greater_than: Required. Integer value
     indicating the age in days after creation
    :type days_after_creation_greater_than: int
    """

    _validation = {
        'days_after_creation_greater_than': {'required': True, 'minimum': 0},
    }

    _attribute_map = {
        'days_after_creation_greater_than': {'key': 'daysAfterCreationGreaterThan', 'type': 'int'},
    }

    def __init__(self, *, days_after_creation_greater_than: int, **kwargs) -> None:
        super(DateAfterCreation, self).__init__(**kwargs)
        self.days_after_creation_greater_than = days_after_creation_greater_than
