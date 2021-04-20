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

from .maps_geofence_event_properties_py3 import MapsGeofenceEventProperties


class MapsGeofenceExitedEventData(MapsGeofenceEventProperties):
    """Schema of the Data property of an EventGridEvent for a
    Microsoft.Maps.GeofenceExited event.

    :param expired_geofence_geometry_id: Lists of the geometry ID of the
     geofence which is expired relative to the user time in the request.
    :type expired_geofence_geometry_id: list[str]
    :param geometries: Lists the fence geometries that either fully contain
     the coordinate position or have an overlap with the searchBuffer around
     the fence.
    :type geometries: list[~azure.eventgrid.models.MapsGeofenceGeometry]
    :param invalid_period_geofence_geometry_id: Lists of the geometry ID of
     the geofence which is in invalid period relative to the user time in the
     request.
    :type invalid_period_geofence_geometry_id: list[str]
    :param is_event_published: True if at least one event is published to the
     Azure Maps event subscriber, false if no event is published to the Azure
     Maps event subscriber.
    :type is_event_published: bool
    """

    _attribute_map = {
        'expired_geofence_geometry_id': {'key': 'expiredGeofenceGeometryId', 'type': '[str]'},
        'geometries': {'key': 'geometries', 'type': '[MapsGeofenceGeometry]'},
        'invalid_period_geofence_geometry_id': {'key': 'invalidPeriodGeofenceGeometryId', 'type': '[str]'},
        'is_event_published': {'key': 'isEventPublished', 'type': 'bool'},
    }

    def __init__(self, *, expired_geofence_geometry_id=None, geometries=None, invalid_period_geofence_geometry_id=None, is_event_published: bool=None, **kwargs) -> None:
        super(MapsGeofenceExitedEventData, self).__init__(expired_geofence_geometry_id=expired_geofence_geometry_id, geometries=geometries, invalid_period_geofence_geometry_id=invalid_period_geofence_geometry_id, is_event_published=is_event_published, **kwargs)