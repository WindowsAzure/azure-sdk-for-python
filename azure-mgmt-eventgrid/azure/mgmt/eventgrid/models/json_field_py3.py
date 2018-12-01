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


class JsonField(Model):
    """This is used to express the source of an input schema mapping for a single
    target field in the Event Grid Event schema. This is currently used in the
    mappings for the 'id','topic' and 'eventTime' properties. This represents a
    field in the input event schema.

    :param source_field: Name of a field in the input event schema that's to
     be used as the source of a mapping.
    :type source_field: str
    """

    _attribute_map = {
        'source_field': {'key': 'sourceField', 'type': 'str'},
    }

    def __init__(self, *, source_field: str=None, **kwargs) -> None:
        super(JsonField, self).__init__(**kwargs)
        self.source_field = source_field
