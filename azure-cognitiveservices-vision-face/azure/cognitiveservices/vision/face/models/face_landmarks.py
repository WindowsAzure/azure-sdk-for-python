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


class FaceLandmarks(Model):
    """A collection of 27-point face landmarks pointing to the important positions
    of face components.

    :param pupil_left:
    :type pupil_left: ~azure.cognitiveservices.vision.face.models.Coordinate
    :param pupil_right:
    :type pupil_right: ~azure.cognitiveservices.vision.face.models.Coordinate
    :param nose_tip:
    :type nose_tip: ~azure.cognitiveservices.vision.face.models.Coordinate
    :param mouth_left:
    :type mouth_left: ~azure.cognitiveservices.vision.face.models.Coordinate
    :param mouth_right:
    :type mouth_right: ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eyebrow_left_outer:
    :type eyebrow_left_outer:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eyebrow_left_inner:
    :type eyebrow_left_inner:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eye_left_outer:
    :type eye_left_outer:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eye_left_top:
    :type eye_left_top: ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eye_left_bottom:
    :type eye_left_bottom:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eye_left_inner:
    :type eye_left_inner:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eyebrow_right_inner:
    :type eyebrow_right_inner:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eyebrow_right_outer:
    :type eyebrow_right_outer:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eye_right_inner:
    :type eye_right_inner:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eye_right_top:
    :type eye_right_top:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eye_right_bottom:
    :type eye_right_bottom:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param eye_right_outer:
    :type eye_right_outer:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param nose_root_left:
    :type nose_root_left:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param nose_root_right:
    :type nose_root_right:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param nose_left_alar_top:
    :type nose_left_alar_top:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param nose_right_alar_top:
    :type nose_right_alar_top:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param nose_left_alar_out_tip:
    :type nose_left_alar_out_tip:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param nose_right_alar_out_tip:
    :type nose_right_alar_out_tip:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param upper_lip_top:
    :type upper_lip_top:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param upper_lip_bottom:
    :type upper_lip_bottom:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param under_lip_top:
    :type under_lip_top:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    :param under_lip_bottom:
    :type under_lip_bottom:
     ~azure.cognitiveservices.vision.face.models.Coordinate
    """

    _attribute_map = {
        'pupil_left': {'key': 'pupilLeft', 'type': 'Coordinate'},
        'pupil_right': {'key': 'pupilRight', 'type': 'Coordinate'},
        'nose_tip': {'key': 'noseTip', 'type': 'Coordinate'},
        'mouth_left': {'key': 'mouthLeft', 'type': 'Coordinate'},
        'mouth_right': {'key': 'mouthRight', 'type': 'Coordinate'},
        'eyebrow_left_outer': {'key': 'eyebrowLeftOuter', 'type': 'Coordinate'},
        'eyebrow_left_inner': {'key': 'eyebrowLeftInner', 'type': 'Coordinate'},
        'eye_left_outer': {'key': 'eyeLeftOuter', 'type': 'Coordinate'},
        'eye_left_top': {'key': 'eyeLeftTop', 'type': 'Coordinate'},
        'eye_left_bottom': {'key': 'eyeLeftBottom', 'type': 'Coordinate'},
        'eye_left_inner': {'key': 'eyeLeftInner', 'type': 'Coordinate'},
        'eyebrow_right_inner': {'key': 'eyebrowRightInner', 'type': 'Coordinate'},
        'eyebrow_right_outer': {'key': 'eyebrowRightOuter', 'type': 'Coordinate'},
        'eye_right_inner': {'key': 'eyeRightInner', 'type': 'Coordinate'},
        'eye_right_top': {'key': 'eyeRightTop', 'type': 'Coordinate'},
        'eye_right_bottom': {'key': 'eyeRightBottom', 'type': 'Coordinate'},
        'eye_right_outer': {'key': 'eyeRightOuter', 'type': 'Coordinate'},
        'nose_root_left': {'key': 'noseRootLeft', 'type': 'Coordinate'},
        'nose_root_right': {'key': 'noseRootRight', 'type': 'Coordinate'},
        'nose_left_alar_top': {'key': 'noseLeftAlarTop', 'type': 'Coordinate'},
        'nose_right_alar_top': {'key': 'noseRightAlarTop', 'type': 'Coordinate'},
        'nose_left_alar_out_tip': {'key': 'noseLeftAlarOutTip', 'type': 'Coordinate'},
        'nose_right_alar_out_tip': {'key': 'noseRightAlarOutTip', 'type': 'Coordinate'},
        'upper_lip_top': {'key': 'upperLipTop', 'type': 'Coordinate'},
        'upper_lip_bottom': {'key': 'upperLipBottom', 'type': 'Coordinate'},
        'under_lip_top': {'key': 'underLipTop', 'type': 'Coordinate'},
        'under_lip_bottom': {'key': 'underLipBottom', 'type': 'Coordinate'},
    }

    def __init__(self, **kwargs):
        super(FaceLandmarks, self).__init__(**kwargs)
        self.pupil_left = kwargs.get('pupil_left', None)
        self.pupil_right = kwargs.get('pupil_right', None)
        self.nose_tip = kwargs.get('nose_tip', None)
        self.mouth_left = kwargs.get('mouth_left', None)
        self.mouth_right = kwargs.get('mouth_right', None)
        self.eyebrow_left_outer = kwargs.get('eyebrow_left_outer', None)
        self.eyebrow_left_inner = kwargs.get('eyebrow_left_inner', None)
        self.eye_left_outer = kwargs.get('eye_left_outer', None)
        self.eye_left_top = kwargs.get('eye_left_top', None)
        self.eye_left_bottom = kwargs.get('eye_left_bottom', None)
        self.eye_left_inner = kwargs.get('eye_left_inner', None)
        self.eyebrow_right_inner = kwargs.get('eyebrow_right_inner', None)
        self.eyebrow_right_outer = kwargs.get('eyebrow_right_outer', None)
        self.eye_right_inner = kwargs.get('eye_right_inner', None)
        self.eye_right_top = kwargs.get('eye_right_top', None)
        self.eye_right_bottom = kwargs.get('eye_right_bottom', None)
        self.eye_right_outer = kwargs.get('eye_right_outer', None)
        self.nose_root_left = kwargs.get('nose_root_left', None)
        self.nose_root_right = kwargs.get('nose_root_right', None)
        self.nose_left_alar_top = kwargs.get('nose_left_alar_top', None)
        self.nose_right_alar_top = kwargs.get('nose_right_alar_top', None)
        self.nose_left_alar_out_tip = kwargs.get('nose_left_alar_out_tip', None)
        self.nose_right_alar_out_tip = kwargs.get('nose_right_alar_out_tip', None)
        self.upper_lip_top = kwargs.get('upper_lip_top', None)
        self.upper_lip_bottom = kwargs.get('upper_lip_bottom', None)
        self.under_lip_top = kwargs.get('under_lip_top', None)
        self.under_lip_bottom = kwargs.get('under_lip_bottom', None)
