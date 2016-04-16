# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.paging import Paged


class EndpointPaged(Paged):
    """
    A paging container for iterating over a list of Endpoint object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[Endpoint]'}
    }

    def __init__(self, *args, **kwargs):

        super(EndpointPaged, self).__init__(*args, **kwargs)
