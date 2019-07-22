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


class CloudError(Model):
    """CloudError.
    """

    _attribute_map = {
    }


class ResourceSku(Model):
    """Describes an available Compute SKU.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar resource_type: The type of resource the SKU applies to.
    :vartype resource_type: str
    :ivar name: The name of SKU.
    :vartype name: str
    :ivar tier: Specifies the tier of virtual machines in a scale set.<br
     /><br /> Possible Values:<br /><br /> **Standard**<br /><br /> **Basic**
    :vartype tier: str
    :ivar size: The Size of the SKU.
    :vartype size: str
    :ivar family: The Family of this particular SKU.
    :vartype family: str
    :ivar kind: The Kind of resources that are supported in this SKU.
    :vartype kind: str
    :ivar capacity: Specifies the number of virtual machines in the scale set.
    :vartype capacity:
     ~azure.mgmt.compute.v2019_04_01.models.ResourceSkuCapacity
    :ivar locations: The set of locations that the SKU is available.
    :vartype locations: list[str]
    :ivar location_info: A list of locations and availability zones in those
     locations where the SKU is available.
    :vartype location_info:
     list[~azure.mgmt.compute.v2019_04_01.models.ResourceSkuLocationInfo]
    :ivar api_versions: The api versions that support this SKU.
    :vartype api_versions: list[str]
    :ivar costs: Metadata for retrieving price info.
    :vartype costs:
     list[~azure.mgmt.compute.v2019_04_01.models.ResourceSkuCosts]
    :ivar capabilities: A name value pair to describe the capability.
    :vartype capabilities:
     list[~azure.mgmt.compute.v2019_04_01.models.ResourceSkuCapabilities]
    :ivar restrictions: The restrictions because of which SKU cannot be used.
     This is empty if there are no restrictions.
    :vartype restrictions:
     list[~azure.mgmt.compute.v2019_04_01.models.ResourceSkuRestrictions]
    """

    _validation = {
        'resource_type': {'readonly': True},
        'name': {'readonly': True},
        'tier': {'readonly': True},
        'size': {'readonly': True},
        'family': {'readonly': True},
        'kind': {'readonly': True},
        'capacity': {'readonly': True},
        'locations': {'readonly': True},
        'location_info': {'readonly': True},
        'api_versions': {'readonly': True},
        'costs': {'readonly': True},
        'capabilities': {'readonly': True},
        'restrictions': {'readonly': True},
    }

    _attribute_map = {
        'resource_type': {'key': 'resourceType', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
        'size': {'key': 'size', 'type': 'str'},
        'family': {'key': 'family', 'type': 'str'},
        'kind': {'key': 'kind', 'type': 'str'},
        'capacity': {'key': 'capacity', 'type': 'ResourceSkuCapacity'},
        'locations': {'key': 'locations', 'type': '[str]'},
        'location_info': {'key': 'locationInfo', 'type': '[ResourceSkuLocationInfo]'},
        'api_versions': {'key': 'apiVersions', 'type': '[str]'},
        'costs': {'key': 'costs', 'type': '[ResourceSkuCosts]'},
        'capabilities': {'key': 'capabilities', 'type': '[ResourceSkuCapabilities]'},
        'restrictions': {'key': 'restrictions', 'type': '[ResourceSkuRestrictions]'},
    }

    def __init__(self, **kwargs):
        super(ResourceSku, self).__init__(**kwargs)
        self.resource_type = None
        self.name = None
        self.tier = None
        self.size = None
        self.family = None
        self.kind = None
        self.capacity = None
        self.locations = None
        self.location_info = None
        self.api_versions = None
        self.costs = None
        self.capabilities = None
        self.restrictions = None


class ResourceSkuCapabilities(Model):
    """Describes The SKU capabilities object.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: An invariant to describe the feature.
    :vartype name: str
    :ivar value: An invariant if the feature is measured by quantity.
    :vartype value: str
    """

    _validation = {
        'name': {'readonly': True},
        'value': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'value': {'key': 'value', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ResourceSkuCapabilities, self).__init__(**kwargs)
        self.name = None
        self.value = None


class ResourceSkuCapacity(Model):
    """Describes scaling information of a SKU.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar minimum: The minimum capacity.
    :vartype minimum: long
    :ivar maximum: The maximum capacity that can be set.
    :vartype maximum: long
    :ivar default: The default capacity.
    :vartype default: long
    :ivar scale_type: The scale type applicable to the sku. Possible values
     include: 'Automatic', 'Manual', 'None'
    :vartype scale_type: str or
     ~azure.mgmt.compute.v2019_04_01.models.ResourceSkuCapacityScaleType
    """

    _validation = {
        'minimum': {'readonly': True},
        'maximum': {'readonly': True},
        'default': {'readonly': True},
        'scale_type': {'readonly': True},
    }

    _attribute_map = {
        'minimum': {'key': 'minimum', 'type': 'long'},
        'maximum': {'key': 'maximum', 'type': 'long'},
        'default': {'key': 'default', 'type': 'long'},
        'scale_type': {'key': 'scaleType', 'type': 'ResourceSkuCapacityScaleType'},
    }

    def __init__(self, **kwargs):
        super(ResourceSkuCapacity, self).__init__(**kwargs)
        self.minimum = None
        self.maximum = None
        self.default = None
        self.scale_type = None


class ResourceSkuCosts(Model):
    """Describes metadata for retrieving price info.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar meter_id: Used for querying price from commerce.
    :vartype meter_id: str
    :ivar quantity: The multiplier is needed to extend the base metered cost.
    :vartype quantity: long
    :ivar extended_unit: An invariant to show the extended unit.
    :vartype extended_unit: str
    """

    _validation = {
        'meter_id': {'readonly': True},
        'quantity': {'readonly': True},
        'extended_unit': {'readonly': True},
    }

    _attribute_map = {
        'meter_id': {'key': 'meterID', 'type': 'str'},
        'quantity': {'key': 'quantity', 'type': 'long'},
        'extended_unit': {'key': 'extendedUnit', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(ResourceSkuCosts, self).__init__(**kwargs)
        self.meter_id = None
        self.quantity = None
        self.extended_unit = None


class ResourceSkuLocationInfo(Model):
    """ResourceSkuLocationInfo.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar location: Location of the SKU
    :vartype location: str
    :ivar zones: List of availability zones where the SKU is supported.
    :vartype zones: list[str]
    :ivar zone_details: Details of capabilities available to a SKU in specific
     zones.
    :vartype zone_details:
     list[~azure.mgmt.compute.v2019_04_01.models.ResourceSkuZoneDetails]
    """

    _validation = {
        'location': {'readonly': True},
        'zones': {'readonly': True},
        'zone_details': {'readonly': True},
    }

    _attribute_map = {
        'location': {'key': 'location', 'type': 'str'},
        'zones': {'key': 'zones', 'type': '[str]'},
        'zone_details': {'key': 'zoneDetails', 'type': '[ResourceSkuZoneDetails]'},
    }

    def __init__(self, **kwargs):
        super(ResourceSkuLocationInfo, self).__init__(**kwargs)
        self.location = None
        self.zones = None
        self.zone_details = None


class ResourceSkuRestrictionInfo(Model):
    """ResourceSkuRestrictionInfo.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar locations: Locations where the SKU is restricted
    :vartype locations: list[str]
    :ivar zones: List of availability zones where the SKU is restricted.
    :vartype zones: list[str]
    """

    _validation = {
        'locations': {'readonly': True},
        'zones': {'readonly': True},
    }

    _attribute_map = {
        'locations': {'key': 'locations', 'type': '[str]'},
        'zones': {'key': 'zones', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ResourceSkuRestrictionInfo, self).__init__(**kwargs)
        self.locations = None
        self.zones = None


class ResourceSkuRestrictions(Model):
    """Describes scaling information of a SKU.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar type: The type of restrictions. Possible values include: 'Location',
     'Zone'
    :vartype type: str or
     ~azure.mgmt.compute.v2019_04_01.models.ResourceSkuRestrictionsType
    :ivar values: The value of restrictions. If the restriction type is set to
     location. This would be different locations where the SKU is restricted.
    :vartype values: list[str]
    :ivar restriction_info: The information about the restriction where the
     SKU cannot be used.
    :vartype restriction_info:
     ~azure.mgmt.compute.v2019_04_01.models.ResourceSkuRestrictionInfo
    :ivar reason_code: The reason for restriction. Possible values include:
     'QuotaId', 'NotAvailableForSubscription'
    :vartype reason_code: str or
     ~azure.mgmt.compute.v2019_04_01.models.ResourceSkuRestrictionsReasonCode
    """

    _validation = {
        'type': {'readonly': True},
        'values': {'readonly': True},
        'restriction_info': {'readonly': True},
        'reason_code': {'readonly': True},
    }

    _attribute_map = {
        'type': {'key': 'type', 'type': 'ResourceSkuRestrictionsType'},
        'values': {'key': 'values', 'type': '[str]'},
        'restriction_info': {'key': 'restrictionInfo', 'type': 'ResourceSkuRestrictionInfo'},
        'reason_code': {'key': 'reasonCode', 'type': 'ResourceSkuRestrictionsReasonCode'},
    }

    def __init__(self, **kwargs):
        super(ResourceSkuRestrictions, self).__init__(**kwargs)
        self.type = None
        self.values = None
        self.restriction_info = None
        self.reason_code = None


class ResourceSkuZoneDetails(Model):
    """Describes The zonal capabilities of a SKU.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar name: The set of zones that the SKU is available in with the
     specified capabilities.
    :vartype name: list[str]
    :ivar capabilities: A list of capabilities that are available for the SKU
     in the specified list of zones.
    :vartype capabilities:
     list[~azure.mgmt.compute.v2019_04_01.models.ResourceSkuCapabilities]
    """

    _validation = {
        'name': {'readonly': True},
        'capabilities': {'readonly': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': '[str]'},
        'capabilities': {'key': 'capabilities', 'type': '[ResourceSkuCapabilities]'},
    }

    def __init__(self, **kwargs):
        super(ResourceSkuZoneDetails, self).__init__(**kwargs)
        self.name = None
        self.capabilities = None
