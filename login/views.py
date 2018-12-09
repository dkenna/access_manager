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
from tokenizer import AuthChallenge, PubKeyChallenge, ChallengeVerifier
from tokenizer import UserToken, UpdateToken, TokenVerifier
from tokenizer import PemValidator
from .forms import *
from django.contrib.auth import authenticate, login
import random

class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

@require_http_methods(["GET"])
def get_update_challenge(request):
    return JsonResponse({"token": PubKeyChallenge().token()})

@require_http_methods(["GET"])
def get_auth_challenge(request):
    return JsonResponse({"token": AuthChallenge().token()})

def _json(body,keys):
    """load json and ensure all keys are present"""
    try:
        payload = json.loads(body)
        for i in keys:
            payload[i]
    except Exception as e:
        print("parsing json failed.")
        raise e
    return payload
    
@require_http_methods(["POST"])
@csrf_exempt
def validate_token(request):
    verifier = ChallengeVerifier()
    try:
        payload = _json(request.body.decode('utf-8'),['token'])
        token = payload['token']
        decoded = challenge.validate_timestamp(token)
        return JsonResponse(decoded)
    except Exception as e:
        print(e)
        return HttpResponseBadRequest()

@require_http_methods(["POST"])
@csrf_exempt
def update_pub_key(request):
    """ update user's public key on the server."""
    try:
        payload = _json(request.body.decode('utf-8'),['username','token','pub_key'])
        verifier = TokenVerifier(payload['token'])
        claims = verifier.verify(payload['username'])
        if not claims: 
            return get_401(request,verifier.errmsg)
        validator = PemValidator()
        pem_stat = validator.validate(payload['pub_key'])
        if pem_stat:
            user = User.objects.get(username=payload['username'])
            #user.profile.public_key = payload['public_key']
            #user.save()
            return JsonResponse({'status':'good'})
        else:
            return get_401(request,validator.errmsg)
    except Exception as e:
        print(type(e))
        print(e)
        print('update key failed')
        return get_401(request)

@require_http_methods(["POST"])
@csrf_exempt
def get_update_token(request):
    """ get an authorization token to update the public key """
    try:
        payload = _json(request.body.decode('utf-8'),['username','signed_challenge'])
        username = payload['username']
        signed_challenge = payload['signed_challenge']
        user = authenticate(request,username=username,signed_challenge=signed_challenge)
        if user is not None:
            return JsonResponse({'update_token':UpdateToken(user).token()})
        else:
            return get_401(request)
    except Exception as e:
        print(type(e))
        print(e)
        return get_401(request)

@require_http_methods(["POST"])
@csrf_exempt
def token_login(request):
    """ simple authentication with a signed challenge return an id_token """
    try:
        payload = _json(request.body.decode('utf-8'),('username','signed_challenge'))
        username = payload['username']
        signed_challenge = payload['signed_challenge']
        user = authenticate(request,username=username,signed_challenge=signed_challenge)
        if user is not None:
            login(request, user)
            return JsonResponse({'id_token':UserToken(user).token()})
        else:
            return get_401(request)
    except Exception as e:
        print(type(e))
        print(e)
        print("token login failed")
        return get_401(request)

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

'''def passphrase_login(request):
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
    return render(request, 'challenge_login.html', {'form': form})'''

@require_http_methods(["POST"])
@csrf_exempt
def passphrase_login_json(request):
    try:
        payload = _json(request.body.decode('utf-8'),['passphrase'])
        passphrase = payload['passphrase']
        user = authenticate(request, passphrase=passphrase)
        if user is not None:
            login(request, user)
            return JsonResponse({'username': user.username, 'update_token':UserToken(user).token()})
        else:
            return get_401(request)
    except Exception as e:
        print(type(e))
        print(e)
        print("token login failed")
        return get_401(request)

def get_json_http_error(request,status,msg):
    print(f'log: status: {status} msg: "{msg}"')
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
def get_401(request,msg="forsbidden"):
    return get_json_http_error(request, 401, msg)
