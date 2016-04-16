# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class WorkflowTriggerRecurrence(Model):
    """WorkflowTriggerRecurrence

    :param frequency: Gets or sets the frequency. Possible values include:
     'Second', 'Minute', 'Hour', 'Day', 'Week', 'Month', 'Year'
    :type frequency: str
    :param interval: Gets or sets the interval.
    :type interval: int
    :param start_time: Gets or sets the start time.
    :type start_time: datetime
    :param time_zone: Gets or sets the time zone.
    :type time_zone: str
    """ 

    _attribute_map = {
        'frequency': {'key': 'frequency', 'type': 'RecurrenceFrequency'},
        'interval': {'key': 'interval', 'type': 'int'},
        'start_time': {'key': 'startTime', 'type': 'iso-8601'},
        'time_zone': {'key': 'timeZone', 'type': 'str'},
    }

    def __init__(self, frequency=None, interval=None, start_time=None, time_zone=None):
        self.frequency = frequency
        self.interval = interval
        self.start_time = start_time
        self.time_zone = time_zone
