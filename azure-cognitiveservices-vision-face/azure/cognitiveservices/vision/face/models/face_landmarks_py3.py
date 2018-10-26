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

    def __init__(self, *, pupil_left=None, pupil_right=None, nose_tip=None, mouth_left=None, mouth_right=None, eyebrow_left_outer=None, eyebrow_left_inner=None, eye_left_outer=None, eye_left_top=None, eye_left_bottom=None, eye_left_inner=None, eyebrow_right_inner=None, eyebrow_right_outer=None, eye_right_inner=None, eye_right_top=None, eye_right_bottom=None, eye_right_outer=None, nose_root_left=None, nose_root_right=None, nose_left_alar_top=None, nose_right_alar_top=None, nose_left_alar_out_tip=None, nose_right_alar_out_tip=None, upper_lip_top=None, upper_lip_bottom=None, under_lip_top=None, under_lip_bottom=None, **kwargs) -> None:
        super(FaceLandmarks, self).__init__(**kwargs)
        self.pupil_left = pupil_left
        self.pupil_right = pupil_right
        self.nose_tip = nose_tip
        self.mouth_left = mouth_left
        self.mouth_right = mouth_right
        self.eyebrow_left_outer = eyebrow_left_outer
        self.eyebrow_left_inner = eyebrow_left_inner
        self.eye_left_outer = eye_left_outer
        self.eye_left_top = eye_left_top
        self.eye_left_bottom = eye_left_bottom
        self.eye_left_inner = eye_left_inner
        self.eyebrow_right_inner = eyebrow_right_inner
        self.eyebrow_right_outer = eyebrow_right_outer
        self.eye_right_inner = eye_right_inner
        self.eye_right_top = eye_right_top
        self.eye_right_bottom = eye_right_bottom
        self.eye_right_outer = eye_right_outer
        self.nose_root_left = nose_root_left
        self.nose_root_right = nose_root_right
        self.nose_left_alar_top = nose_left_alar_top
        self.nose_right_alar_top = nose_right_alar_top
        self.nose_left_alar_out_tip = nose_left_alar_out_tip
        self.nose_right_alar_out_tip = nose_right_alar_out_tip
        self.upper_lip_top = upper_lip_top
        self.upper_lip_bottom = upper_lip_bottom
        self.under_lip_top = under_lip_top
        self.under_lip_bottom = under_lip_bottom
