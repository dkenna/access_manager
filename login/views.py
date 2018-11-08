from django.shortcuts import render
from login.models import Profile
from django.contrib.auth.models import User
from rest_framework import routers, serializers, viewsets

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email')

class ProfileSerializer(serializers.ModelSerializer):
    #user = serializers.HyperlinkedRelatedField( many=False, read_only=True, view_name='user-detail')
    user = UserSerializer(many=False, read_only=True)
    class Meta:
        model = Profile
        fields = ('public_key','private_key','user')

class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

