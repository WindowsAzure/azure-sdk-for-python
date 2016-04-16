# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.paging import Paged


class AvailabilitySetPaged(Paged):
    """
    A paging container for iterating over a list of AvailabilitySet object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[AvailabilitySet]'}
    }

    def __init__(self, *args, **kwargs):

        super(AvailabilitySetPaged, self).__init__(*args, **kwargs)
