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

from .resource_py3 import Resource


class Forecast(Resource):
    """A forecast resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource Id.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar tags: Resource tags.
    :vartype tags: dict[str, str]
    :ivar usage_date: The usage date of the forecast.
    :vartype usage_date: str
    :param grain: The granularity of forecast. Possible values include:
     'Daily', 'Monthly', 'Yearly'
    :type grain: str or ~azure.mgmt.consumption.models.Grain
    :ivar charge: The amount of charge
    :vartype charge: decimal.Decimal
    :ivar currency: The ISO currency in which the meter is charged, for
     example, USD.
    :vartype currency: str
    :param charge_type: The type of the charge. Could be actual or forecast.
     Possible values include: 'Actual', 'Forecast'
    :type charge_type: str or ~azure.mgmt.consumption.models.ChargeType
    :ivar confidence_levels: The details about the forecast confidence levels.
     This is populated only when chargeType is Forecast.
    :vartype confidence_levels:
     list[~azure.mgmt.consumption.models.ForecastPropertiesConfidenceLevelsItem]
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'tags': {'readonly': True},
        'usage_date': {'readonly': True},
        'charge': {'readonly': True},
        'currency': {'readonly': True},
        'confidence_levels': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'usage_date': {'key': 'properties.usageDate', 'type': 'str'},
        'grain': {'key': 'properties.grain', 'type': 'str'},
        'charge': {'key': 'properties.charge', 'type': 'decimal'},
        'currency': {'key': 'properties.currency', 'type': 'str'},
        'charge_type': {'key': 'properties.chargeType', 'type': 'str'},
        'confidence_levels': {'key': 'properties.confidenceLevels', 'type': '[ForecastPropertiesConfidenceLevelsItem]'},
    }

    def __init__(self, *, grain=None, charge_type=None, **kwargs) -> None:
        super(Forecast, self).__init__(**kwargs)
        self.usage_date = None
        self.grain = grain
        self.charge = None
        self.currency = None
        self.charge_type = charge_type
        self.confidence_levels = None
