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


class FieldValue(Model):
    """Recognized field value.

    All required parameters must be populated in order to send to Azure.

    :param type: Required. Type of field value. Possible values include:
     'string', 'date', 'time', 'phoneNumber', 'number', 'integer', 'array',
     'object'
    :type type: str or
     ~azure.cognitiveservices.formrecognizer.models.FieldValueType
    :param value_string: String value.
    :type value_string: str
    :param value_date: Date value.
    :type value_date: datetime
    :param value_time: Time value.
    :type value_time: str
    :param value_phone_number: Phone number value.
    :type value_phone_number: str
    :param value_number: Floating point value.
    :type value_number: float
    :param value_integer: Integer value.
    :type value_integer: int
    :param value_array: Array of field values.
    :type value_array:
     list[~azure.cognitiveservices.formrecognizer.models.FieldValue]
    :param value_object: Dictionary of named field values.
    :type value_object: dict[str,
     ~azure.cognitiveservices.formrecognizer.models.FieldValue]
    :param text: Required. Extracted text content of the recognized field.
    :type text: str
    :param bounding_box: Bounding box of the field text, if appropriate.
    :type bounding_box: list[float]
    :param confidence: Required. Qualitative confidence measure.
    :type confidence: float
    :param elements: List element references.
    :type elements: list[str]
    """

    _validation = {
        'type': {'required': True},
        'text': {'required': True},
        'confidence': {'required': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'FieldValueType'},
        'value_string': {'key': 'valueString', 'type': 'str'},
        'value_date': {'key': 'valueDate', 'type': 'iso-8601'},
        'value_time': {'key': 'valueTime', 'type': 'str'},
        'value_phone_number': {'key': 'valuePhoneNumber', 'type': 'str'},
        'value_number': {'key': 'valueNumber', 'type': 'float'},
        'value_integer': {'key': 'valueInteger', 'type': 'int'},
        'value_array': {'key': 'valueArray', 'type': '[FieldValue]'},
        'value_object': {'key': 'valueObject', 'type': '{FieldValue}'},
        'text': {'key': 'text', 'type': 'str'},
        'bounding_box': {'key': 'boundingBox', 'type': '[float]'},
        'confidence': {'key': 'confidence', 'type': 'float'},
        'elements': {'key': 'elements', 'type': '[str]'},
    }

    def __init__(self, *, type, text: str, confidence: float, value_string: str=None, value_date=None, value_time: str=None, value_phone_number: str=None, value_number: float=None, value_integer: int=None, value_array=None, value_object=None, bounding_box=None, elements=None, **kwargs) -> None:
        super(FieldValue, self).__init__(**kwargs)
        self.type = type
        self.value_string = value_string
        self.value_date = value_date
        self.value_time = value_time
        self.value_phone_number = value_phone_number
        self.value_number = value_number
        self.value_integer = value_integer
        self.value_array = value_array
        self.value_object = value_object
        self.text = text
        self.bounding_box = bounding_box
        self.confidence = confidence
        self.elements = elements
