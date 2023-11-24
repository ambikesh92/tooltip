
from django.http.response import JsonResponse,HttpResponse
from django.shortcuts import redirect
from rest_framework.parsers import JSONParser 
from rest_framework import status, viewsets
 
from inventory.models import InventoryAttribute, InventoryItem, ToolltipData
from inventory.serializers import InventoryImageSerializer, InventorySerializer, TooltipdataSerializer
from rest_framework.decorators import api_view


from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status, permissions

from django.contrib.auth.models import User
from inventory.serializers import UserSerializer

from django.core.mail import send_mail
from .serializers import UserSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, PasswordReset
from django.contrib import messages
from rest_framework.exceptions import AuthenticationFailed
import jwt, datetime, random, string
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from rest_framework import generics, status, exceptions
from django.urls import reverse
from django.conf import settings

#function/view for checking if the request is by authenticated user & if it is retrieves the User ID from the JWT

def checkToken(request):
    #extracts the token from the headers in the HTTP request added by the angular interceptor on each request
    token = request.headers['Authorization']
    if not token:
            raise AuthenticationFailed('Unauthenticated')
    payload = jwt.decode(token, 'secret', algorithms =['HS256'])
    user = User.objects.filter(id = payload['id']).first()
    return user
    
#view for registering anew user
class RegisterView(APIView):
    def post(self, request):    
        serializer = UserSerializer(data = request.data)
        try:
            serializer.is_valid(raise_exception = True)
        except:
            return Response("User already exists!")
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email2 = user_data['email2'])
        token = RefreshToken.for_user(user).access_token  #generates a random acccess token
        current_site = get_current_site(request).domain #gets the current site domain link
        relativeLink = reverse ('email-verify') #reversing the URL
        absurl = 'http://'+ current_site + relativeLink+"?tkn="+ str(token)
        email_body = 'Hi'+user.name + 'Use Link below to verify your email\n'+absurl
        data = {'email_body' : email_body, 'to_email': user.email2, 'email_subject': 'Hover2Discover: Verify your email'}
        Util.send_email(data)

        return Response ('Hi ' +user_data['name'] +"! Your account has been created. Please check " +user_data['email2'] +' to veify your email!' )

#view when user clicks on the email verification link
class VerifyEmail(generics.GenericAPIView):
    def get(self, request):
        token = request.GET.get('tkn')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response ('Account Successfully activated!')
        except jwt.ExpiredSignatureError as identifier:
            return Response ('Activation Link Expired')
        except jwt.exceptions.DecodeError as identifier:
            return Response ('Error: Invalid Token!')
        
        
#view for resetting user Password
class ResetPassword(APIView):
      def post(self, request):
        password = request.POST.get('password')
        confirmPassword = request.POST.get('confirmPassword')
        frntToken = request.POST.get('token')
        
        passwordReset = PasswordReset.objects.filter(token = frntToken).first()
        user= User.objects.filter(email2 = passwordReset.email2).first()
        if not user:
            raise exceptions.NotFound('User not found!')
        user.set_password(password)
        user.save()
        return Response ('Password successfully updated!!')
      
#view for changing the user password        
class PasswordChange (APIView):
     def post(self, request):
        token = request.headers['Authorization']
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        payload = jwt.decode(token, 'secret', algorithms =['HS256'])
        user = User.objects.filter(id = payload['id']).first()
          
#view for forgot user password       
class ForgetPassword(APIView):
      def post(self, request):
        userEmail = request.POST.get('email2')
        user =User.objects.filter(email2 = userEmail). first()
        if user is None:
            return Response ('This user does not exist!' )
        
        token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range (12))  #generates a random acccess token to be added at the end of the redirect URL
        userExists = PasswordReset.objects.filter(email2 = userEmail)
        if userExists is not None:
             userExists.delete()

        PasswordReset.objects.create(email2 = userEmail, token = token)

        send_mail(
             subject= "Please reset your password!",
             message = 'Hi'+ userEmail + '\n \nWe received a request to change password for this account. Please use the link below to reset the password:\n\n'+'http://localhost:4200/reset-password/'+ token,
             from_email= "inventtooltips@gmail.com",
             recipient_list= [userEmail]
        )
        return Response ('Please check your email!' )


#view for logging into the app
class LoginView(APIView):
    def post (self, request):
        email2 = request.data['email2']
        password = request.data ['password']

        user = User.objects.filter(email2 = email2).first()
        response = Response()
        if user is None:
            response.data = {
            
             'message': 'Username is incorrect!'
           
            }
            return response
        

        if not user.check_password(password):
            response.data = {
            
             'message': 'Password is Incorrect!'
           
            }
            return response

            
        #encoding the user id into the payload of the token
        payload = {
            'id': user.id,
            'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow(),
            
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')
        
        
        response.data = {
            
           'jwt': token,
           'message': 'Login was Successful!'
           
        }
        
        return response

class UserView(APIView):
    def get(self, request):

            token = request.headers['Authorization']
            if not token:
                raise AuthenticationFailed('Unauthenticated')
            try:
                payload = jwt.decode(token, 'secret', algorithms =['HS256'])
            except jwt.ExpiredSignatureError:
                raise AuthenticationFailed('Unauthenticated')
            user = User.objects.filter(id = payload['id']).first()
            serializer = UserSerializer(user)


            return Response(serializer.data)

class LogoutView(APIView):
            def post(self, request):
                response = Response()
                response.delete_cookie('jwt')
                response.data={
                    'message': 'success'
                }

                return response
class ForgotPassword(APIView):
    def post(self, request):
        email2 = request.data['email2']
        token = ''.join(random.choice(string.ascii_uppercase +string.digits) for _ in range(12))
        PasswordReset.objects.create(email2 = email2, token = token)
        send_mail (
            subject = 'Activate your mail',
            message = 'Click <a href ="http://localhost:8000/reset/' + token + '> here</a> toactivate your account',
            from_email= 'inventtooltips@gmail.com',
            recipient_list=[email2]
        )
        return Response ({
            ''
        })

#delete inventory item
@api_view(['GET', 'POST', 'DELETE'])
def inventory_delete(request):
 if(request.method == 'DELETE'):
    inventoryImage = InventoryItem.objects.all()
    imageID = request.GET.get('id',  None)
#filter to the correct record based on the id from the frontend
#django deletes the associated records in foreign key relationships by the default relationship!
    inventoryImage.filter(id = imageID).delete()
    return JsonResponse({'message': 'Inventory Item was deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)
 
#delete inventory attribute
@api_view(['GET', 'POST', 'DELETE'])
def attribute_delete(request):
 if(request.method == 'DELETE'):
    inventoryAttribute = InventoryAttribute.objects.all()
    attributeID = request.GET.get('id',  None)
#filter to the correct record based on the id from the frontend
#django deletes the associated records in foreign key relationships by the default relationship!
    inventoryAttribute.filter(id = attributeID ).delete()
    return JsonResponse({'message': 'Inventory Item was deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET', 'POST', 'DELETE'])
def inventory_deleteAttribute(request, delete_item):
 if(request.method == 'DELETE'):
    inventoryAttribute = InventoryAttribute.objects.get(pk = delete_item)
    inventoryAttribute.delete()
    return JsonResponse({'message': 'Inventory Item was deleted successfully!'}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET', 'POST', 'DELETE'])
def inventory_Search(request):
#check JWT token for user id then display full list of items where user id matches the id in the token
    user = checkToken(request)
    id2 = user.id   

    inventoryDisplay = InventoryItem.objects.filter(inventoryUser = id2)     
    if request.method == 'GET':
               
            imageName2 = request.GET.get('imageName',  None)
            if imageName2 is not None:
                    inventoryDisplay = inventoryDisplay.filter(imageName__icontains=imageName2)
            inventory_image_serializer= InventoryImageSerializer(inventoryDisplay, many = True)
            return JsonResponse(inventory_image_serializer.data, safe=False)


@api_view(['GET', 'POST', 'DELETE'])
def inventory_Load(request):
  
    inventoryDisplay = InventoryItem.objects.all()     
    if request.method == 'GET':
               
            imageName2 = request.GET.get('id',  None)
            if imageName2 is not None:
                    inventoryDisplay = inventoryDisplay.filter(imageName=imageName2)
            inventory_image_serializer= InventoryImageSerializer(inventoryDisplay, many = True)
            return JsonResponse(inventory_image_serializer.data, safe=False)           

#view for retrieving inventory image of the passed index
@api_view(['GET', 'POST', 'DELETE'])
def inventory_Retrieve(request):
    user = checkToken(request)
    inventoryDisplay = InventoryItem.objects.all()     

    if request.method == 'GET':
            #get id from the JSON/parsed by the Serializer into the Python type
            imageName2 = request.GET.get('id',  None)
            if imageName2 is not None:
                    #filter to the item with the correct id
                    inventoryDisplay = inventoryDisplay.filter(pk=imageName2)
                  
            #return JSON with the correct image
            inventory_image_serializer= InventoryImageSerializer(inventoryDisplay, many = True)
          
            return JsonResponse(inventory_image_serializer.data, safe=False)
                     
#view for retrieving tooltipdata of attribute endex
@api_view(['GET', 'POST', 'DELETE'])
def tooltip_Retrieve(request):
  
    tooltipDisplay = ToolltipData.objects.all()     

    if request.method == 'GET':
            #get id from the JSON/parsed by the Serializer into the Python type
            
            attrName = request.GET.get('id',  None)
            result = []
            for ids in attrName.split(','):
                    result.append (int(ids))
           
            #filter to the item with the correct id
            tooltipDisplay = tooltipDisplay.filter(attributeName__in= result)
                  
            #return JSON with the correct image
            tooltip_serializer= TooltipdataSerializer(tooltipDisplay, many = True)
          
            return JsonResponse(tooltip_serializer.data, safe=False)


@api_view(['GET', 'POST', 'DELETE'])
def inventory_Attributes(request):
  
    inventoryAttributes = InventoryAttribute.objects.all()
    if request.method == 'GET':
            #get id from the JSON/parsed by the Serializer into the Python type
            imageName2 = request.GET.get('id',  None)
            if imageName2 is not None:
                    #filter to the item with the correct id
                   
                    inventoryAttributes = inventoryAttributes.filter(imageNameLink = imageName2)
            #return JSON with the correct image
        
            inventory_attribute_serializer = InventorySerializer(inventoryAttributes, many = True)
            return JsonResponse(inventory_attribute_serializer.data, safe=False)    

#view function for returning all the attributes in database
@api_view(['GET', 'POST', 'DELETE'])
def inventory_Attributes_All(request):
  
    inventoryAttributes = InventoryAttribute.objects.all()
    if request.method == 'GET':
            inventory_attribute_serializer = InventorySerializer(inventoryAttributes, many = True)
            return JsonResponse(inventory_attribute_serializer.data, safe=False)              

#view function for posting Inventory Item in the database
class InvntoryImageView(APIView):
    def post (self, request):
        token = request.headers['Authorization']
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        payload = jwt.decode(token, 'secret', algorithms =['HS256'])
        user = User.objects.filter(id = payload['id']).first()
        imageActual = request.data['imageActual']
        imageName = request.data['imageName']
        privacySetting = request.data['privacySetting']
        inventoryCategory = request.data['inventoryCategory']
        inventoryLocation = request.data['inventoryLocation']
        inventoryitem = InventoryItem( 
            imageName = imageName, imageActual = imageActual, inventoryLocation = inventoryLocation,
            privacySetting = privacySetting, inventoryCategory = inventoryCategory,
            inventoryUser = user )
        inventoryitem.save()
        return JsonResponse({'message': 'Inventory Item was created successfully!'}, status=status.HTTP_204_NO_CONTENT)

    
#view for storing tooltipdata
class InventoryViewSet1 (viewsets.ModelViewSet):
    queryset = ToolltipData.objects.all()
    serializer_class = TooltipdataSerializer
  

    def post (self, request, *args, **kwargs):
        
        tooltipIframe = request.data['tooltipIframe']
        tooltipImage = request.data['tooltipImage']
        tooltipText = request.data['tooltipText']
        attributeName = request.data['attributeName']
        ToolltipData.objects.create(tooltipIframe = tooltipIframe, tooltipImage = tooltipImage, tooltipText=tooltipText,attributeName=attributeName)
        return HttpResponse({'message':'Inventory Item Created!'}, staus = 200)

class InventoryViewSet2 (viewsets.ModelViewSet):
    queryset = ToolltipData.objects.all()
    serializer_class = TooltipdataSerializer
    

    def post (self, request, *args, **kwargs):
        tooltipIframe = request.data['tooltipIframe']
        tooltipText = request.data['tooltipText']
        attributeName = request.data['attributeName']
        ToolltipData.objects.create(tooltipIframe = tooltipIframe, tooltipText=tooltipText,attributeName=attributeName)
        return HttpResponse({'message':'Inventory Item Created!'}, staus = 200)



   
#view for handling inventory attribute name + SVG

@api_view(['GET', 'POST', 'DELETE'])
def inventory_list(request):
    if request.method == 'GET':
        tutorial = InventoryAttribute.objects.all()
        
        attrName = request.GET.get('attrName', None)
        if attrName is not None:
            tutorial = tutorial.filter(attrName__icontains=attrName)
        
        tutorials_serializer = InventorySerializer(tutorial, many=True)
        return JsonResponse(tutorials_serializer.data, safe=False)
        # 'safe=False' for objects serialization

    elif request.method == 'POST':
     
        tutorial_data = JSONParser().parse(request)
        tutorial_serializer = InventorySerializer(data=tutorial_data)
        if tutorial_serializer.is_valid():
            tutorial_serializer.save()
            return JsonResponse(tutorial_serializer.data, status=status.HTTP_201_CREATED) 
        return JsonResponse(tutorial_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
def inventory_detail(request, pk):
    # ... tutorial = Tutorial.objects.get(pk=pk)
    tutorial = InventoryAttribute.objects.all()
    if request.method == 'GET': 
        tutorial_serializer = InventorySerializer(tutorial) 
        return JsonResponse(tutorial_serializer.data) 

    elif request.method == 'PUT': 
        tutorial_data = JSONParser().parse(request) 
        tutorial_serializer = InventorySerializer(tutorial, data=tutorial_data) 
        if tutorial_serializer.is_valid(): 
            tutorial_serializer.save() 
            return JsonResponse(tutorial_serializer.data) 
        return JsonResponse(tutorial_serializer.errors, status=status.HTTP_400_BAD_REQUEST) 

    elif request.method == 'DELETE': 
        tutorial.delete() 
        return JsonResponse({'message': 'Tutorial was deleted successfully!'}, status=200)

    elif request.method == 'DELETE':
        count = InventoryAttribute.objects.all().delete()
        return JsonResponse({'message': '{} Tutorials were deleted successfully!'.format(count[0])}, status=status.HTTP_204_NO_CONTENT)

@api_view(['GET', 'POST', 'DELETE'])
def inventory_list(request):
    if request.method == 'GET':
        tutorial = InventoryAttribute.objects.all()
        
        attrName = request.GET.get('attrName', None)
        if attrName is not None:
            tutorial = tutorial.filter(attrName__icontains=attrName)
        
        tutorials_serializer = InventorySerializer(tutorial, many=True)
        return JsonResponse(tutorials_serializer.data, safe=False)
        # 'safe=False' for objects serialization

    elif request.method == 'POST':
        inventory_data = JSONParser().parse(request)
        inventory_attribute_serializer = InventorySerializer(data=inventory_data)
        if inventory_attribute_serializer.is_valid():
            
            inventory_attribute_serializer.save()
            return JsonResponse(inventory_attribute_serializer.data, status=status.HTTP_201_CREATED) 
        return JsonResponse(inventory_attribute_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#view for handling update of privacy setting
@api_view(['GET', 'POST', 'DELETE'])
def privacy_Update(request, *kwargs):
    #check if privacy update is being made by an authorized user by checking the JWT in the header
    user = checkToken(request)
    id2 = user.id  
    if request.method == 'POST':
      
        inventoryID = request.POST['id']
        inventoryPrivacy = request.POST['privacy']
        InventoryItem.objects.filter(pk= inventoryID).update(privacySetting = inventoryPrivacy)
        inventoryDisplay =  InventoryItem.objects.filter(pk= inventoryID)      
        inventory_image_serializer= InventoryImageSerializer(inventoryDisplay,  many=True)
          
        return JsonResponse(inventory_image_serializer.data, safe=False)

#view for searching public items listed by user        
@api_view(['GET', 'POST', 'DELETE'])
def user_search (request):
   
   #no need to check token in this case as we are only searching for publically listed items
       if request.method == 'GET':
              
           userName = request.GET.get('userName',  None)
           if  userName != None and  userName is not '':
           #select the relevant user from database
                selectUser = User.objects.filter(email2__icontains=userName)
                length = selectUser.count()
                #filter to inventory item objects associated with user - append all ids to an array
                result = []
                for id  in range(length):
                            result.append (getattr(selectUser[id], 'pk')) #returning back user objects 
            
                inventoryItems = InventoryItem.objects.filter(inventoryUser__in = result)
                #filter to inventory item objects associated with user that have privacy set to public
                inventoryItems =  inventoryItems.filter(privacySetting = 'public')
                #return all the publically listed inventory items related to the
                inventory_image_serializer= InventoryImageSerializer(inventoryItems, many = True)
                return JsonResponse(inventory_image_serializer.data, safe=False)
       return JsonResponse(inventory_image_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                
                           
#view for displaying all publically listed inventory items
@api_view(['GET', 'POST', 'DELETE'])
def inventory_Public_Search(request):
    
    if request.method == 'GET':
    
            imageName2 = request.GET.get('imageName',  None)
            if imageName2 is not None and imageName2 is not '':
                    inventoryDisplay = InventoryItem.objects.filter(imageName__icontains=imageName2)
                    inventoryDisplay = inventoryDisplay.filter(privacySetting = 'public')
            inventory_image_serializer= InventoryImageSerializer(inventoryDisplay, many = True)
            return JsonResponse(inventory_image_serializer.data, safe=False)


#view for displaying all publically listed inventory items related to an attribute
@api_view(['GET', 'POST', 'DELETE'])
def attribute_Public_Search(request):
    
    if request.method == 'GET':
               
            attributeName= request.GET.get('attributeName',  None)
            if attributeName is not None and attributeName is not '':
                #filter to all attributes that match the search
                    attributeRelevant = InventoryAttribute.objects.filter(attrName__icontains = attributeName)
                    length = attributeRelevant.count()  #count associated attributes so that relevant InventoryItem ids can be retrieved
                    result = [] #iterate over the attributes and store the foreign key in result
                    for id2  in range(length):
                        val = (getattr(attributeRelevant[id2], 'imageNameLink')) #retrieve all inventoryItem objects associated with the id
                        privacy = (getattr(val, 'privacySetting')) #retrieves value of items set to Public 
                        if privacy == 'public':
                            result.append (val)
  
            inventory_image_serializer= InventoryImageSerializer(result, many = True)
            return JsonResponse(inventory_image_serializer.data, safe=False)
    

#view for displaying all publically listed inventory category items
@api_view(['GET', 'POST', 'DELETE'])
def category_Public_Search(request):
    
    if request.method == 'GET':

            if request.method == 'GET':
                categoryName= request.GET.get('category',  None)
                if categoryName is not None and categoryName is not '':
                        inventoryDisplay = InventoryItem.objects.filter(inventoryCategory__icontains=categoryName)
                        inventoryDisplay = inventoryDisplay.filter(privacySetting = 'public')
                inventory_image_serializer= InventoryImageSerializer(inventoryDisplay, many = True)
                return JsonResponse(inventory_image_serializer.data, safe=False)
            

#view for displaying all publically listed inventory items by location
@api_view(['GET', 'POST', 'DELETE'])
def location_Public_Search(request):
    
    if request.method == 'GET':
            if request.method == 'GET':
                categoryName= request.GET.get('location',  None)
                if categoryName is not None and categoryName is not '':
                        inventoryDisplay = InventoryItem.objects.filter(inventoryLocation__icontains=categoryName)
                        inventoryDisplay = inventoryDisplay.filter(privacySetting = 'public')
                inventory_image_serializer= InventoryImageSerializer(inventoryDisplay, many = True)
                return JsonResponse(inventory_image_serializer.data, safe=False)

#view for updating image name
@api_view(['GET', 'POST', 'DELETE'])
def updateImageName(request):
        
        #authorized requests only 
        token = request.headers['Authorization']
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        payload = jwt.decode(token, 'secret', algorithms =['HS256'])
        user = User.objects.filter(id = payload['id']).first()
        imageID = request.data['imageID']
        imageName = request.data['imageName']
        #udpate imageName to the new one sent by the user
        InventoryItem.objects.filter(id = imageID).update(imageName = imageName)

        response = Response()
        response.data = {
            
             'message': 'Item Name updated Successfully!'
           
            }
        return response


#view for updating attribute name + SVG
@api_view(['GET', 'POST', 'DELETE'])
def updateAttributeName(request):
        
        #authorized requests only 
        token = request.headers['Authorization']
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        payload = jwt.decode(token, 'secret', algorithms =['HS256'])
        user = User.objects.filter(id = payload['id']).first()
        attrID = request.data['attrID']
        attrName = request.data['attrName']
        attrSVG = request.data['attrSVG']
        #udpate imageName to the new one sent by the user
        InventoryAttribute.objects.filter(id = attrID).update(attrName = attrName, attrSVG = attrSVG)

        response = Response()
        response.data = {
            
             'message': 'Item Name updated Successfully!'
           
            }
        return response
        
        
       
       