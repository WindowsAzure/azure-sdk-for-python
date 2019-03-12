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

from .properties_item import PropertiesItem


class Rating(PropertiesItem):
    """Defines a rating.

    You probably want to use the sub-classes and not this class directly. Known
    sub-classes are: AggregateRating

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar text: Text representation of an item.
    :vartype text: str
    :param _type: Required. Constant filled by server.
    :type _type: str
    :param rating_value: Required. The mean (average) rating. The possible
     values are 1.0 through 5.0.
    :type rating_value: float
    :ivar best_rating: The highest rated review. The possible values are 1.0
     through 5.0.
    :vartype best_rating: float
    """

    _validation = {
        'text': {'readonly': True},
        '_type': {'required': True},
        'rating_value': {'required': True},
        'best_rating': {'readonly': True},
    }

    _attribute_map = {
        'text': {'key': 'text', 'type': 'str'},
        '_type': {'key': '_type', 'type': 'str'},
        'rating_value': {'key': 'ratingValue', 'type': 'float'},
        'best_rating': {'key': 'bestRating', 'type': 'float'},
    }

    _subtype_map = {
        '_type': {'AggregateRating': 'AggregateRating'}
    }

    def __init__(self, *, rating_value: float, **kwargs) -> None:
        super(Rating, self).__init__(**kwargs)
        self.rating_value = rating_value
        self.best_rating = None
        self._type = 'Rating'
