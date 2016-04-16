# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.paging import Paged


class UserPaged(Paged):
    """
    A paging container for iterating over a list of User object
    """

    _attribute_map = {
        'next_link': {'key': 'odata.nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[User]'}
    }

    def __init__(self, *args, **kwargs):

        super(UserPaged, self).__init__(*args, **kwargs)
