from django.shortcuts import render
from login.models import *
from django.contrib.auth.models import User
from rest_framework import routers, serializers, viewsets
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from jwt.exceptions import InvalidSignatureError 
import json
from login.serializers import *
from tokenizer import AuthChallenge, KeyChallenge, UserToken
from .forms import *
from django.contrib.auth import authenticate, login
import random

class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

def create_session(user):
    session = TokenSession()
    session.user = user
    session.save()

@require_http_methods(["GET"])
def get_update_challenge(request):
    return JsonResponse({"token": KeyChallenge().token()})

@require_http_methods(["GET"])
def get_auth_challenge(request):
    return JsonResponse({"token": AuthChallenge().token()})

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
def token_login(request):
    """
        Simple authentication with a signed token
    """
    try:
        body = request.body.decode('utf-8')
        payload = json.loads(body)
        username = payload['username']
        signed_challenge = payload['signed_challenge']
        user = authenticate(request,username=username,signed_challenge=signed_challenge)
        if user is not None:
            login(request, user)
            return JsonResponse({'token':UserToken(user).token()})
        else:
            return get_401(request)
    except Exception as e:
        print(type(e))
        print(e)
        return get_401(request)
    pass


def challenge_login(request):
    if request.method == 'POST':
        form = ChallengeLoginForm(request.POST)
        if form.is_valid():
            signed_challenge = form.cleaned_data['signed_challenge']
            username = form.cleaned_data['username']
            user = authenticate(request,username=username,signed_challenge=signed_challenge)
            if user is not None:
                login(request, user)
                next_url = request.GET.get('next')
                if next_url:
                    print('redirecting to: ' + next_url)
                    return HttpResponseRedirect(next_url)
                return HttpResponseRedirect('/')
    else:
        form = ChallengeLoginForm()
    return render(request, 'challenge_login.html', {'form': form})

def passphrase_login(request):
    if request.method == 'POST':
        form = PassphraseLoginForm(request.POST)
        if form.is_valid():
            passphrase = form.cleaned_data['passphrase']
            username = form.cleaned_data['username']
            user = authenticate(request,username=username,passphrase=passphrase)
            if user is not None:
                login(request, user)
                next_url = request.GET.get('next')
                if next_url:
                    print('redirecting to: ' + next_url)
                    return HttpResponseRedirect(next_url)
                return HttpResponseRedirect('/')
    else:
        form = PassphraseLoginForm()
    return render(request, 'challenge_login.html', {'form': form})

def get_json_http_error(request,status,msg):
    return JsonResponse(status=status, data={
        'status': 'error',
        'error': msg
    })

@csrf_exempt
def get_404(request):
    return get_json_http_error(request, 404,"not ffffound")

@csrf_exempt
def get_400(request):
    return get_json_http_error(request, 400, "bad requesssst")

@csrf_exempt
def get_405(request):
    return get_json_http_error(request, 400, "bad meth")

@csrf_exempt
def get_401(request):
    return get_json_http_error(request, 401, "forbsidden")
