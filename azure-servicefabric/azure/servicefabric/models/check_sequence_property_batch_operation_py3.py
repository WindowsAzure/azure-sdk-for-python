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

from .property_batch_operation import PropertyBatchOperation


class CheckSequencePropertyBatchOperation(PropertyBatchOperation):
    """Compares the Sequence Number of a property with the SequenceNumber
    argument.
    A property's sequence number can be thought of as that property's version.
    Every time the property is modified, its sequence number is increased.
    The sequence number can be found in a property's metadata.
    The comparison fails if the sequence numbers are not equal.
    CheckSequencePropertyBatchOperation is generally used as a precondition for
    the write operations in the batch.
    Note that if one PropertyBatchOperation in a PropertyBatch fails,
    the entire batch fails and cannot be committed in a transactional manner.
    .

    All required parameters must be populated in order to send to Azure.

    :param property_name: Required. The name of the Service Fabric property.
    :type property_name: str
    :param kind: Required. Constant filled by server.
    :type kind: str
    :param sequence_number: Required. The expected sequence number.
    :type sequence_number: str
    """

    _validation = {
        'property_name': {'required': True},
        'kind': {'required': True},
        'sequence_number': {'required': True},
    }

    _attribute_map = {
        'property_name': {'key': 'PropertyName', 'type': 'str'},
        'kind': {'key': 'Kind', 'type': 'str'},
        'sequence_number': {'key': 'SequenceNumber', 'type': 'str'},
    }

    def __init__(self, *, property_name: str, sequence_number: str, **kwargs) -> None:
        super(CheckSequencePropertyBatchOperation, self).__init__(property_name=property_name, **kwargs)
        self.sequence_number = sequence_number
        self.kind = 'CheckSequence'
