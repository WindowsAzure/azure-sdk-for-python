# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.paging import Paged


class NamespaceResourcePaged(Paged):
    """
    A paging container for iterating over a list of NamespaceResource object
    """

    _attribute_map = {
        'next_link': {'key': 'nextLink', 'type': 'str'},
        'current_page': {'key': 'value', 'type': '[NamespaceResource]'}
    }

    def __init__(self, *args, **kwargs):

        super(NamespaceResourcePaged, self).__init__(*args, **kwargs)
