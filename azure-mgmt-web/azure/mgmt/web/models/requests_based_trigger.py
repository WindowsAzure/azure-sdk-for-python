# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class RequestsBasedTrigger(Model):
    """
    RequestsBasedTrigger

    :param count: Count
    :type count: int
    :param time_interval: TimeInterval
    :type time_interval: str
    """ 

    _attribute_map = {
        'count': {'key': 'count', 'type': 'int'},
        'time_interval': {'key': 'timeInterval', 'type': 'str'},
    }

    def __init__(self, count=None, time_interval=None):
        self.count = count
        self.time_interval = time_interval
