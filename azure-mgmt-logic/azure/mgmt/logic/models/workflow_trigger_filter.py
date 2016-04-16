# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator 0.16.0.0
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class WorkflowTriggerFilter(Model):
    """WorkflowTriggerFilter

    :param state: Gets or sets the state of workflow trigger. Possible values
     include: 'NotSpecified', 'Enabled', 'Disabled', 'Deleted', 'Suspended'
    :type state: str
    """ 

    _attribute_map = {
        'state': {'key': 'state', 'type': 'WorkflowState'},
    }

    def __init__(self, state=None):
        self.state = state
