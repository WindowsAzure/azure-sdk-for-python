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


class Annotation(Model):
    """Annotation associated with an application insights resource.

    :param annotation_name: Name of annotation
    :type annotation_name: str
    :param category: Category of annotation, free form
    :type category: str
    :param event_time: Time when event occurred
    :type event_time: datetime
    :param id: Unique Id for annotation
    :type id: str
    :param properties: Serialized JSON object for detailed properties
    :type properties: str
    :param related_annotation: Related parent annotation if any. Default
     value: "null" .
    :type related_annotation: str
    """

    _attribute_map = {
        'annotation_name': {'key': 'AnnotationName', 'type': 'str'},
        'category': {'key': 'Category', 'type': 'str'},
        'event_time': {'key': 'EventTime', 'type': 'iso-8601'},
        'id': {'key': 'Id', 'type': 'str'},
        'properties': {'key': 'Properties', 'type': 'str'},
        'related_annotation': {'key': 'RelatedAnnotation', 'type': 'str'},
    }

    def __init__(self, annotation_name=None, category=None, event_time=None, id=None, properties=None, related_annotation="null"):
        super(Annotation, self).__init__()
        self.annotation_name = annotation_name
        self.category = category
        self.event_time = event_time
        self.id = id
        self.properties = properties
        self.related_annotation = related_annotation
