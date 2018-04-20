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


class ChaosTargetFilter(Model):
    """Defines all filters for targeted Chaos faults, for example, faulting only
    certain node types or faulting only certain applications.
    If ChaosTargetFilter is not used, Chaos faults all cluster entities. If
    ChaosTargetFilter is used, Chaos faults only the entities that meet the
    ChaosTargetFilter
    specification. NodeTypeInclusionList and ApplicationInclusionList allow a
    union semantics only. It is not possible to specify an intersection
    of NodeTypeInclusionList and ApplicationInclusionList. For example, it is
    not possible to specify "fault this application only when it is on that
    node type."
    Once an entity is included in either NodeTypeInclusionList or
    ApplicationInclusionList, that entity cannot be excluded using
    ChaosTargetFilter. Even if
    applicationX does not appear in ApplicationInclusionList, in some Chaos
    iteration applicationX can be faulted because it happens to be on a node of
    nodeTypeY that is included
    in NodeTypeInclusionList. If both NodeTypeInclusionList and
    ApplicationInclusionList are null or empty, an ArgumentException is thrown.

    :param node_type_inclusion_list: A list of node types to include in Chaos
     faults.
     All types of faults (restart node, restart code package, remove replica,
     restart replica, move primary, and move secondary) are enabled for the
     nodes of these node types.
     If a nodetype (say NodeTypeX) does not appear in the
     NodeTypeInclusionList, then node level faults (like NodeRestart) will
     never be enabled for the nodes of
     NodeTypeX, but code package and replica faults can still be enabled for
     NodeTypeX if an application in the ApplicationInclusionList.
     happens to reside on a node of NodeTypeX.
     At most 100 node type names can be included in this list, to increase this
     number, a config upgrade is required for
     MaxNumberOfNodeTypesInChaosEntityFilter configuration.
    :type node_type_inclusion_list: list[str]
    :param application_inclusion_list: A list of application URI's to include
     in Chaos faults.
     All replicas belonging to services of these applications are amenable to
     replica faults (restart replica, remove replica, move primary, and move
     secondary) by Chaos.
     Chaos may restart a code package only if the code package hosts replicas
     of these applications only.
     If an application does not appear in this list, it can still be faulted in
     some Chaos iteration if the application ends up on a node of a node type
     that is included in NodeTypeInclusionList.
     However, if applicationX is tied to nodeTypeY through placement
     constraints and applicationX is absent from ApplicationInclusionList and
     nodeTypeY is absent from NodeTypeInclusionList, then applicationX will
     never be faulted.
     At most 1000 application names can be included in this list, to increase
     this number, a config upgrade is required for
     MaxNumberOfApplicationsInChaosEntityFilter configuration.
    :type application_inclusion_list: list[str]
    """

    _attribute_map = {
        'node_type_inclusion_list': {'key': 'NodeTypeInclusionList', 'type': '[str]'},
        'application_inclusion_list': {'key': 'ApplicationInclusionList', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(ChaosTargetFilter, self).__init__(**kwargs)
        self.node_type_inclusion_list = kwargs.get('node_type_inclusion_list', None)
        self.application_inclusion_list = kwargs.get('application_inclusion_list', None)
