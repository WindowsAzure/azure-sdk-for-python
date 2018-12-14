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


class AlertFeedback(Model):
    """The alert feedback details.

    :param level: The alert level which indicates the severity of the alert.
    :type level: str
    :param state: The alert state which can be either active or resolved with
     multiple resolution types.
    :type state: str
    :param short_name: The alert short name.
    :type short_name: str
    :param feedback: The feedback for the alert which indicates if the
     customer likes or dislikes the alert.
    :type feedback: str
    :param comment: Additional comments related to the alert.
    :type comment: str
    :param consented_to_share: Indicates if the alert feedback can be shared
     from product team.
    :type consented_to_share: bool
    :param service_member_id: The server Id of the alert.
    :type service_member_id: str
    :param created_date: The date and time,in UTC,when the alert was created.
    :type created_date: datetime
    """

    _attribute_map = {
        'level': {'key': 'level', 'type': 'str'},
        'state': {'key': 'state', 'type': 'str'},
        'short_name': {'key': 'shortName', 'type': 'str'},
        'feedback': {'key': 'feedback', 'type': 'str'},
        'comment': {'key': 'comment', 'type': 'str'},
        'consented_to_share': {'key': 'consentedToShare', 'type': 'bool'},
        'service_member_id': {'key': 'serviceMemberId', 'type': 'str'},
        'created_date': {'key': 'createdDate', 'type': 'iso-8601'},
    }

    def __init__(self, **kwargs):
        super(AlertFeedback, self).__init__(**kwargs)
        self.level = kwargs.get('level', None)
        self.state = kwargs.get('state', None)
        self.short_name = kwargs.get('short_name', None)
        self.feedback = kwargs.get('feedback', None)
        self.comment = kwargs.get('comment', None)
        self.consented_to_share = kwargs.get('consented_to_share', None)
        self.service_member_id = kwargs.get('service_member_id', None)
        self.created_date = kwargs.get('created_date', None)
