# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
from enum import Enum

from .models import (
    CommunicationIdentifierModel,
    CommunicationUserIdentifier,
    PhoneNumberIdentifier,
    MicrosoftTeamsUserIdentifier,
    UnknownIdentifier,
    CommunicationUserIdentifierModel,
    PhoneNumberIdentifierModel,
    MicrosoftTeamsUserIdentifierModel
)

class _IdentifierType(Enum):
    COMMUNICATION_USER_IDENTIFIER=1
    PHONE_NUMBER_IDENTIFIER=2
    UNKNOWN_IDENTIFIER=3
    MICROSOFT_TEAMS_IDENTIFIER=4

class CommunicationUserIdentifierSerializer(object):

    @classmethod
    def serialize(cls, communicationIdentifier):
        """ Serialize the Communication identifier into CommunicationIdentifierModel

        :param identifier: Identifier object
        :type identifier: Union[CommunicationUserIdentifier,
           PhoneNumberIdentifier, MicrosoftTeamsUserIdentifier, UnknownIdentifier]
        :return: CommunicationIdentifierModel
        :rtype: ~azure.communication.chat.CommunicationIdentifierModel
        :raises Union[TypeError, ValueError]
        """
        if isinstance(communicationIdentifier, CommunicationUserIdentifier):
            return CommunicationIdentifierModel(
                communication_user=CommunicationUserIdentifierModel(id=communicationIdentifier.identifier)
            )
        if isinstance(communicationIdentifier, PhoneNumberIdentifier):
            return CommunicationIdentifierModel(
                raw_id=communicationIdentifier.raw_id,
                phone_number=PhoneNumberIdentifierModel(value=communicationIdentifier.phone_number)
            )
        if isinstance(communicationIdentifier, MicrosoftTeamsUserIdentifier):
            return CommunicationIdentifierModel(
                raw_id=communicationIdentifier.raw_id,
                microsoft_teams_user=MicrosoftTeamsUserIdentifierModel(user_id=communicationIdentifier.user_id,
                is_anonymous=communicationIdentifier.is_anonymous,
                cloud=communicationIdentifier.cloud)
            )

        if isinstance(communicationIdentifier, UnknownIdentifier):
            return CommunicationIdentifierModel(
                raw_id=communicationIdentifier.identifier
            )

        raise TypeError("Unsupported identifier type " + communicationIdentifier.__class__.__name__)

    @classmethod
    def assertMaximumOneNestedModel(cls, identifierModel):
        presentPropertiesCount = 0
        if identifierModel.communication_user is not None:
            presentPropertiesCount += 1
        if identifierModel.phone_number is not None:
            presentPropertiesCount += 1
        if identifierModel.microsoft_teams_user is not None:
            presentPropertiesCount += 1

        if presentPropertiesCount > 1:
            raise ValueError("Only one of the properties in identifier model should be present.")

    @classmethod
    def deserialize(cls, identifierModel):
        """
        Deserialize the CommunicationIdentifierModel into Communication Identifier

        :param identifierModel: CommunicationIdentifierModel
        :type identifierModel: CommunicationIdentifierModel
        :return: Union[CommunicationUserIdentifier, CommunicationPhoneNumberIdentifier]
        :rtype: Union[CommunicationUserIdentifier, CommunicationPhoneNumberIdentifier]
        :rasies: ValueError
        """

        raw_id = identifierModel.raw_id
        if not raw_id:
            raise ValueError("Identifier must have a valid id")

        CommunicationUserIdentifierSerializer.assertMaximumOneNestedModel(identifierModel)

        if identifierModel.communication_user is not None:
            return CommunicationUserIdentifier(raw_id)
        if identifierModel.phone_number is not None:
            if not identifierModel.phone_number:
                raise ValueError("PhoneNumberIdentifier must have a valid attribute - phone_number")
            return PhoneNumberIdentifier(identifierModel.phone_number.value, raw_id=raw_id)
        if identifierModel.microsoft_teams_user is not None:
            if identifierModel.microsoft_teams_user.is_anonymous not in [True, False]:
                raise ValueError("MicrosoftTeamsUser must have a valid attribute - is_anonymous")
            if not identifierModel.microsoft_teams_user.user_id:
                raise ValueError("MicrosoftTeamsUser must have a valid attribute - user_id")
            if not identifierModel.microsoft_teams_user.cloud:
                raise ValueError("MicrosoftTeamsUser must have a valid attribute - cloud")
            return MicrosoftTeamsUserIdentifier(
                raw_id=raw_id,
                user_id=identifierModel.microsoft_teams_user.user_id,
                is_anonymous=identifierModel.microsoft_teams_user.is_anonymous,
                cloud=identifierModel.microsoft_teams_user.cloud
            )

        return UnknownIdentifier(raw_id)

    @classmethod
    def _getIdnetifierType(cls, communicationIdentifier):
        def has_attributes(object, attributes):
            return all([hasattr(communicationIdentifier, attr) for attr in attributes])

        if has_attributes(communicationIdentifier, ["identifier"]):
            return _IdentifierType.COMMUNICATION_USER_IDENTIFIER
        
        if has_attributes(communicationIdentifier, ['phone_number', 'raw_id']):
            return _IdentifierType.PHONE_NUMBER_IDENTIFIER
        
        if has_attributes(communicationIdentifier, ["raw_id", "user_id", "is_anonymous", "cloud"]):
            return _IdentifierType.MICROSOFT_TEAMS_IDENTIFIER

        # TODO: replace the schema of UnknownIdentifier
        if has_attributes(communicationIdentifier, ["identifier"]):
            return _IdentifierType.UNKNOWN_IDENTIFIER

