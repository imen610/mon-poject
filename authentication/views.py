from django.shortcuts import render

# Create your views here.


from django.shortcuts import render
from rest_framework import generics, status,views
from django.conf import settings
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode


from cashless.settings import SECRET_KEY
from  .serializers import LoginSerializer, RegisterSerializer, EmailVerificationSerializer,RestPasswordEmailRequestSerialiser , SetNewPasswordSerializer
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from cashless.utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str,force_str , smart_bytes ,DjangoUnicodeDecodeError
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from cashless.utils import Util

    

from authentication import serializers
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
# Create your views here.


class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer


    def post(self,request):
        user=request.data
        serializer=self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save() 

        user_data=serializer.data 
        
        user =User.objects.get(email=user_data['email'])

        token=RefreshToken.for_user(user).access_token
        current_site=get_current_site(request).domain
        
        relativeLink=reverse('email-verify')
        absurl='http://'+ str(current_site)+str(relativeLink)+"?token="+str(token)
        email_body='hi'+user.username+'Use link below to verify your email \n' + absurl
        data={'email_body':email_body ,'to_email':user.email,'email_subject':'Verify your email'}
        
   
        Util.send_email(data)

        return Response(user_data,status=status.HTTP_201_CREATED)


class verifyEmail(views.APIView):

    serializer_class=EmailVerificationSerializer

    #token_param_config=openapi.Parameter('token',in_=openapi.IN_QUERY,description='description',type=openapi.TYPE_STRING)
    
    
    #@swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self,request):
        token = request.GET.get('token')
        
        try:
            payload = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
            user=User.objects.get(id=payload['user_id'])
            if not user.is_verified: 
                user.is_verified = True
                user.save()
            return Response({'email':'Successfully activated'},status=status.HTTP_201_CREATED)
        except jwt.ExpiredSignatureError as identifier :
            return Response({'error':'Activation expired'},status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier :
            return Response({'error':'Invalid token'},status=status.HTTP_400_BAD_REQUEST)
        

    
class LoginAPIView(generics.GenericAPIView):

    
    
    serializer_class = LoginSerializer

    
    def post(self,request):
        
        print(request.data['email'])
        print(request.data['password'])
        serializer=LoginSerializer(data=request.data)
       # user=User.objects.filter(email=request.data['email'],password=request.data['password']).first()
        if serializer.is_valid():
        
            data=serializer.save()
            print("hello")
            return Response(data,status=status.HTTP_200_OK)

  
    
    
class RequestPasswordRestEmail(generics.GenericAPIView):

    serializer_class = RestPasswordEmailRequestSerialiser

    def post(self,request):
        serializer= self.serializer_class(data=request.data)
        email= request.data['email']
        if User.objects.filter(email=email).exists():
                user=User.objects.filter(email=email).first()
                uidb64=urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site=get_current_site(request=request).domain
        
                relativeLink=reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
                absurl='http://'+ str(current_site)+str(relativeLink)
                email_body='hello ,\n Use link below to reset  your password \n' + absurl
                data={'email_body':email_body ,'to_email':user.email,'email_subject':'reset your password'}
    
                Util.send_email(data)
        return Response({'success':'we have sent you a link to reset your password'},status=status.HTTP_200_OK)

class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self,request,uidb64,token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({'error':'Token is not valid , please request a new one'})
            
            return Response({'success':True,'message':'Credentials Valid','uidb64':uidb64,'token':token},status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
                if not PasswordResetTokenGenerator().check_token(user):
                    return Response({'error' : 'Token is not valid , please request a new one'})

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class=SetNewPasswordSerializer

    def patch(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True,'message':'Password reset success'},status=status.HTTP_200_OK)

 