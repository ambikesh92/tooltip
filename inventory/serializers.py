from rest_framework import serializers 
from inventory.models import  InventoryItem, InventoryAttribute, ToolltipData

from .models import User

#serializer for the User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
            model = User
            fields = ['id', 'name', 'email2', 'password']
            extra_kwargs = {
                'password' : {'write_only': True}
            }
#hashing the password logic
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        #django function for hashing the password
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance


#inventory Attribute serializer - using slugField imageName to associate each attribute to the correct image

class InventorySerializer(serializers.ModelSerializer):
 
   class Meta:
        model = InventoryAttribute
        fields = ('id',
                  'attrName',
                  'attrSVG',
                  'imageNameLink',
                  )
#Inventory Item Serializer - associate inventory attribute class to the item object
class InventoryImageSerializer(serializers.ModelSerializer):
   
    class Meta:
        model = InventoryItem
        fields = ('id', 'imageName', 'imageActual', 'privacySetting', 'inventoryCategory', 'inventoryLocation', 'inventoryUser' )

#Inventory Item Serializer for GLTF Object- associate inventory attribute class to the item object
class InventoryModelSerializer(serializers.ModelSerializer):
   
    class Meta:
        model = InventoryItem
        fields = ('id', 'modelName', 'modelGLTF', 'privacySetting', 'inventoryUser' )


#Inventory Tootlip Data Serializer - associate each tooltip data to the correct attribute when passing to the frontend

class TooltipdataSerializer(serializers.ModelSerializer):
   
    class Meta:
        model = ToolltipData
        fields = ('id',
                'tooltipIframe',
                'tooltipImage',
                'tooltipText',
                'attributeName')
