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


class FaceAttributes(Model):
    """Face Attributes.

    :param age: Age in years
    :type age: float
    :param gender: Possible gender of the face. Possible values include:
     'male', 'female'
    :type gender: str or ~azure.cognitiveservices.vision.face.models.Gender
    :param smile: Smile intensity, a number between [0,1]
    :type smile: float
    :param facial_hair:
    :type facial_hair:
     ~azure.cognitiveservices.vision.face.models.FacialHairProperties
    :param glasses: Glasses type if any of the face. Possible values include:
     'noGlasses', 'readingGlasses', 'sunglasses', 'swimmingGoggles'
    :type glasses: str or
     ~azure.cognitiveservices.vision.face.models.GlassesTypes
    :param head_pose:
    :type head_pose:
     ~azure.cognitiveservices.vision.face.models.HeadPoseProperties
    :param emotion:
    :type emotion:
     ~azure.cognitiveservices.vision.face.models.EmotionProperties
    :param hair:
    :type hair: ~azure.cognitiveservices.vision.face.models.HairProperties
    :param makeup:
    :type makeup: ~azure.cognitiveservices.vision.face.models.MakeupProperties
    :param occlusion:
    :type occlusion:
     ~azure.cognitiveservices.vision.face.models.OcclusionProperties
    :param accessories:
    :type accessories:
     list[~azure.cognitiveservices.vision.face.models.AccessoryItem]
    :param blur:
    :type blur: ~azure.cognitiveservices.vision.face.models.BlurProperties
    :param exposure:
    :type exposure:
     ~azure.cognitiveservices.vision.face.models.ExposureProperties
    :param noise:
    :type noise: ~azure.cognitiveservices.vision.face.models.NoiseProperties
    """

    _validation = {
        'smile': {'maximum': 1, 'minimum': 0},
    }

    _attribute_map = {
        'age': {'key': 'age', 'type': 'float'},
        'gender': {'key': 'gender', 'type': 'Gender'},
        'smile': {'key': 'smile', 'type': 'float'},
        'facial_hair': {'key': 'facialHair', 'type': 'FacialHairProperties'},
        'glasses': {'key': 'glasses', 'type': 'GlassesTypes'},
        'head_pose': {'key': 'headPose', 'type': 'HeadPoseProperties'},
        'emotion': {'key': 'emotion', 'type': 'EmotionProperties'},
        'hair': {'key': 'hair', 'type': 'HairProperties'},
        'makeup': {'key': 'makeup', 'type': 'MakeupProperties'},
        'occlusion': {'key': 'occlusion', 'type': 'OcclusionProperties'},
        'accessories': {'key': 'accessories', 'type': '[AccessoryItem]'},
        'blur': {'key': 'blur', 'type': 'BlurProperties'},
        'exposure': {'key': 'exposure', 'type': 'ExposureProperties'},
        'noise': {'key': 'noise', 'type': 'NoiseProperties'},
    }

    def __init__(self, age=None, gender=None, smile=None, facial_hair=None, glasses=None, head_pose=None, emotion=None, hair=None, makeup=None, occlusion=None, accessories=None, blur=None, exposure=None, noise=None):
        self.age = age
        self.gender = gender
        self.smile = smile
        self.facial_hair = facial_hair
        self.glasses = glasses
        self.head_pose = head_pose
        self.emotion = emotion
        self.hair = hair
        self.makeup = makeup
        self.occlusion = occlusion
        self.accessories = accessories
        self.blur = blur
        self.exposure = exposure
        self.noise = noise
