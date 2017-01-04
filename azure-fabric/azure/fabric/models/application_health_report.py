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

from .health_report import HealthReport


class ApplicationHealthReport(HealthReport):
    """The report of the application health.

    :param source_id:
    :type source_id: str
    :param property:
    :type property: str
    :param health_state: Possible values include: 'Invalid', 'Ok', 'Warning',
     'Error', 'Unknown'
    :type health_state: str or :class:`enum <azure.fabric.models.enum>`
    :param description:
    :type description: str
    :param time_to_live_in_milli_seconds:
    :type time_to_live_in_milli_seconds: str
    :param sequence_number:
    :type sequence_number: str
    :param remove_when_expired:
    :type remove_when_expired: bool
    """

    def __init__(self, source_id=None, property=None, health_state=None, description=None, time_to_live_in_milli_seconds=None, sequence_number=None, remove_when_expired=None):
        super(ApplicationHealthReport, self).__init__(source_id=source_id, property=property, health_state=health_state, description=description, time_to_live_in_milli_seconds=time_to_live_in_milli_seconds, sequence_number=sequence_number, remove_when_expired=remove_when_expired)
