from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
import uuid

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    rsa_public_key = models.TextField(blank=True)
    rsa_private_key = models.TextField(blank=True)
    ecdsa_public_key = models.CharField(max_length=512,blank=True)
    ecdsa_private_key = models.CharField(max_length=512, blank=True)
    seed = models.CharField(max_length=512, blank=True)
    passphrase = models.CharField(max_length=2048, blank=True)
    passphrase_hash = models.CharField(max_length=2048, blank=True)    

    def __str__(self):
        return self.passphrase_hash

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

class Challenge(models.Model):
    timestamp = models.DateTimeField()
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    signed_challenge = models.TextField(blank=True)

class TokenSession(models.Model):
    STATUS = (('OPN','OPEN'),('CLD','CLOSED'))
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    sid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    django_sid = models.CharField(max_length=250,blank=True)
    status = models.CharField(max_length=2, choices=STATUS, default='OPN')
