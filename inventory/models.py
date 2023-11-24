from django.db import models

#user token authentication imports - DRF(Django Rest Framework)
from django.contrib.auth.models import User, Group
from django.conf import settings
from django.dispatch import receiver
from django.db.models.signals import post_save
from rest_framework.authtoken.models import Token

from django.db import models
from django.contrib.auth.models import AbstractUser
from .managers import UserManager


def upload_path(instance, filename):
        return '/'.join(['inventory', str(instance.imageName), filename])

#class for storing the inventory item image
def upload_path2(instance, filename):
        return '/'.join(['inventory', str("Data"), filename])

#user model extensding Abstract User using email as the main username field
    
class User(AbstractUser):
    name = models.CharField(max_length=255)
    email2 = models.CharField(max_length=255, unique=True, default ='g')
    password = models.CharField(max_length=255)
    is_verified = models.BooleanField(default = False)
    username = None
   
    USERNAME_FIELD = 'email2'
    REQUIRED_FILEDS = ['username']
    objects = UserManager()
   
class PasswordReset (models.Model):
    email2 = models.CharField(max_length=255, unique=True, default ='g')
    token = models.CharField(max_length=255, unique=True)

#Inventory Item model - each item has a one to many relationship with attributes, each user has many-to-one relationship with inventory items

class InventoryItem(models.Model):
    imageName = models.CharField(max_length = 50, default= None, blank = True, null = True)
    privacySetting = models.CharField(max_length = 50, default= 'Private', blank = True, null = True)
    imageActual = models.ImageField(upload_to= upload_path, blank = True, null=True)
    inventoryUser = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null = True)
    inventoryCategory = models.CharField(max_length = 50, default= None, blank = True, null = True)
    inventoryLocation = models.CharField(max_length = 50, default= None, blank = True, null = True)
#Inventory Model - used for storing 3d GLTF models

class InventoryModel(models.Model):
    modelName = models.CharField(max_length = 50, default= None, blank = True, null = True)
    privacySetting = models.CharField(max_length = 50, default= 'Private', blank = True, null = True)
    modelGLTF = models.ImageField(upload_to= upload_path, blank = True, null=True)
    inventoryUserKey = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null = True)


#model class for storing the attributes
class InventoryAttribute(models.Model):
    attrName = models.CharField (max_length = 50, default= None)
    attrSVG = models.TextField (max_length = 8000, default= None)   
    imageNameLink = models.ForeignKey(InventoryItem, on_delete=models.CASCADE, default = 1, null = True)

#model class for storing the tooltip information - each info piece is a foreign keyed to an attribute   
class ToolltipData(models.Model):
    tooltipIframe = models.TextField(max_length=9000, default = None)  #front-end will display the link as an iframe
    tooltipImage = models.ImageField(upload_to = upload_path2, blank=True, null = True, default='settings.MEDIA_ROOT/logo.jpg') #if the users tooltip data is an image
    tooltipText = models.TextField(max_length=9000, default = None) #if the user only enter just a text
    attributeName = models.ForeignKey(InventoryAttribute,on_delete=models.CASCADE, default = 1, null = True) #each dta is foreign key to the attribute it is associated to

