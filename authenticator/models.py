from django.db import models
from login.models import Profile

class Authenticator(models.Model):
    pass

class Proof(models.Model):
    pass

class ChallengeRequest(models.Model):
    timestamp = models.DateTimeField()
    signed_timestamp = models.CharField(max_length=1024)

class Challenge(models.Model):
    timestamp = models.DateTimeField()
    profile = models.ForeignKey(Profile,on_delete=models.PROTECT)
    signed_challenge = models.CharField(max_length=1024)

class SubscriptionRequest(models.Model):
    proof = models.CharField(max_length=1024)
    public_key = models.TextField(max_length=500, blank=True)
    pass

class Subscription(models.Model):
    pass
