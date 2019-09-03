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

from .resource_py3 import Resource


class Case(Resource):
    """Represents a case in Azure Security Insights.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    All required parameters must be populated in order to send to Azure.

    :ivar id: Azure resource Id
    :vartype id: str
    :ivar name: Azure resource name
    :vartype name: str
    :ivar type: Azure resource type
    :vartype type: str
    :param etag: Etag of the alert rule.
    :type etag: str
    :ivar case_number: a sequential number
    :vartype case_number: int
    :param close_reason: The reason the case was closed. Possible values
     include: 'Resolved', 'Dismissed', 'TruePositive', 'FalsePositive', 'Other'
    :type close_reason: str or ~azure.mgmt.securityinsight.models.CloseReason
    :param closed_reason_text: the case close reason details
    :type closed_reason_text: str
    :ivar created_time_utc: The time the case was created
    :vartype created_time_utc: datetime
    :param description: The description of the case
    :type description: str
    :param end_time_utc: The end time of the case
    :type end_time_utc: datetime
    :param labels: List of labels relevant to this case
    :type labels: list[str]
    :ivar last_comment: the last comment in the case
    :vartype last_comment: str
    :ivar last_updated_time_utc: The last time the case was updated
    :vartype last_updated_time_utc: datetime
    :param owner: Describes a user that the case is assigned to
    :type owner: ~azure.mgmt.securityinsight.models.UserInfo
    :ivar related_alert_ids: List of related alert identifiers
    :vartype related_alert_ids: list[str]
    :param severity: Required. The severity of the case. Possible values
     include: 'Critical', 'High', 'Medium', 'Low', 'Informational'
    :type severity: str or ~azure.mgmt.securityinsight.models.CaseSeverity
    :param start_time_utc: Required. The start time of the case
    :type start_time_utc: datetime
    :param status: Required. The status of the case. Possible values include:
     'Draft', 'New', 'InProgress', 'Closed'
    :type status: str or ~azure.mgmt.securityinsight.models.CaseStatus
    :param title: Required. The title of the case
    :type title: str
    :ivar total_comments: the number of total comments in the case
    :vartype total_comments: int
    """

    _validation = {
        'id': {'readonly': True},
        'name': {'readonly': True},
        'type': {'readonly': True},
        'case_number': {'readonly': True},
        'created_time_utc': {'readonly': True},
        'last_comment': {'readonly': True},
        'last_updated_time_utc': {'readonly': True},
        'related_alert_ids': {'readonly': True},
        'severity': {'required': True},
        'start_time_utc': {'required': True},
        'status': {'required': True},
        'title': {'required': True},
        'total_comments': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'case_number': {'key': 'properties.caseNumber', 'type': 'int'},
        'close_reason': {'key': 'properties.closeReason', 'type': 'str'},
        'closed_reason_text': {'key': 'properties.closedReasonText', 'type': 'str'},
        'created_time_utc': {'key': 'properties.createdTimeUtc', 'type': 'iso-8601'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'end_time_utc': {'key': 'properties.endTimeUtc', 'type': 'iso-8601'},
        'labels': {'key': 'properties.labels', 'type': '[str]'},
        'last_comment': {'key': 'properties.lastComment', 'type': 'str'},
        'last_updated_time_utc': {'key': 'properties.lastUpdatedTimeUtc', 'type': 'iso-8601'},
        'owner': {'key': 'properties.owner', 'type': 'UserInfo'},
        'related_alert_ids': {'key': 'properties.relatedAlertIds', 'type': '[str]'},
        'severity': {'key': 'properties.severity', 'type': 'str'},
        'start_time_utc': {'key': 'properties.startTimeUtc', 'type': 'iso-8601'},
        'status': {'key': 'properties.status', 'type': 'str'},
        'title': {'key': 'properties.title', 'type': 'str'},
        'total_comments': {'key': 'properties.totalComments', 'type': 'int'},
    }

    def __init__(self, *, severity, start_time_utc, status, title: str, etag: str=None, close_reason=None, closed_reason_text: str=None, description: str=None, end_time_utc=None, labels=None, owner=None, **kwargs) -> None:
        super(Case, self).__init__(**kwargs)
        self.etag = etag
        self.case_number = None
        self.close_reason = close_reason
        self.closed_reason_text = closed_reason_text
        self.created_time_utc = None
        self.description = description
        self.end_time_utc = end_time_utc
        self.labels = labels
        self.last_comment = None
        self.last_updated_time_utc = None
        self.owner = owner
        self.related_alert_ids = None
        self.severity = severity
        self.start_time_utc = start_time_utc
        self.status = status
        self.title = title
        self.total_comments = None
