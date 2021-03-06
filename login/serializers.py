from rest_framework import serializers
from login.views import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id','username', 'email','first_name','last_name')

class ProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(many=False, read_only=True)
    class Meta:
        model = Profile
        #fields = ('id','public_key','private_key', 'passphrase','user')
        fields = ('id','rsa_public_key','ecdsa_public_key','user')
