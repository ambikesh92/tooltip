from django.urls import include, re_path

from django.urls import path
from inventory import views
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework import routers
from .views import RegisterView, LoginView,UserView,LogoutView,ForgotPassword, VerifyEmail,InvntoryImageView, ForgetPassword,ResetPassword


urlpatterns = [

    path('api/inventory', views.inventory_list),  #view for retrieving full inventory                          
    path('api/inventory/deleteInventory/', views.inventory_delete), #view for deleting an inventory item
    path('api/inventory/deleteAttribute/', views.attribute_delete), #view for deleting an attribute
    path('api/inventory/searchInventory/', views.inventory_Search), #view for searching through the inventory
    path('api/inventory/searchPublicInventory/', views.inventory_Public_Search), #view for searching only publically listed items
    path('api/inventory/searchPublicAtrribute/', views.attribute_Public_Search), #view to search by attribute of publically listed items
    path('api/inventory/searchPublicCategory/', views.category_Public_Search), #view to search by attribute of publically listed items
    path('api/inventory/searchPublicLocation/', views.location_Public_Search), #view to search by attribute of publically listed items
    path('api/inventory/updateImageName/', views.updateImageName), #view to search by attribute of publically listed items
    path('api/inventory/updateAttributeName/', views.updateAttributeName), #view to update attribute Name + SVG at given ID
    path('api/inventory/upload/', InvntoryImageView.as_view()),
    path('api/inventory/loadInventory/', views.inventory_Load),
    path('api/inventory/retrieveInventory/', views.inventory_Retrieve),
    path('api/inventory/retrieveAllAttributes/', views.inventory_Attributes_All), #view for retrieving length of all the stored attributes
    path('api/inventory/retrieveAttributes/', views.inventory_Attributes),
    path('api/inventory/tooltipData/', views.tooltip_Retrieve), #view for returning tooltipdata
    path('api/inventory/privacySetting/', views.privacy_Update),
    path('api/inventory/searchUser/', views.user_search),    
    path('api/inventory/deleteInventoryAttribute/<delete_item>', views.inventory_deleteAttribute),
    path('api/inventory/auth/', ObtainAuthToken.as_view()),
    re_path(r'^api/inventory/(?P<pk>[0-9]+)$', views.inventory_detail),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
     
    path('register', RegisterView.as_view() ),
    path('passForget', ForgetPassword.as_view() ),
    path('login', LoginView.as_view() ),
    path('user', UserView.as_view() ),
    path('logout', LogoutView.as_view() ),
    path('forgot', ForgotPassword.as_view() ),
    #name allows URL reversal - get the full path of the URL from the name using the django reverse function
    path('email-verify', VerifyEmail.as_view(), name = 'email-verify' ),
    path('reset-password', ResetPassword.as_view() )

]

