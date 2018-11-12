from django.shortcuts import render
from login.models import Profile
from django.contrib.auth.models import User
from rest_framework import routers, serializers, viewsets
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from jwt.exceptions import InvalidSignatureError 
import json
from login.serializers import *
from token_generator import Challenge, SignedChallengeVerifier
from token_generator import Token, ChallengeToken

class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

@require_http_methods(["GET"])
def get_token(request):
    token = ChallengeToken().signed()
    return JsonResponse({"token":token})

@require_http_methods(["POST"])
@csrf_exempt
def validate_token(request):
    challenge = Challenge()
    try:
        body = request.body.decode('utf-8')
        payload = json.loads(body)
        token = payload['token']
        decoded = challenge.validate_timestamp(token)
        return JsonResponse(decoded)
    except Exception as e:
        print(e)
        return HttpResponseBadRequest()

@require_http_methods(["POST"])
@csrf_exempt
def login(request):
    """
        Simple authentication with a signed token
    """
    verifier = SignedChallengeVerifier()
    try:
        body = request.body.decode('utf-8')
        payload = json.loads(body)
        username = payload['username']
        signed_challenge = payload['signed_challenge']
        verifier = SignedChallengeVerifier()
        decoded = verifier.verify_sig(username,signed_challenge)
        verifier.verify_timestamp(decoded["timestamp"])
        return JsonResponse(decoded)
    except Exception as e:
        print(e)
        return HttpResponseBadRequest()
    pass
