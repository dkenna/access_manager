from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField(blank=True)
    private_key = models.TextField(blank=True)
    seed = models.TextField(blank=True)

    def __str__(self):
        return self.user.username + " Profile"

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()

class Challenge(models.Model):
    timestamp = models.DateTimeField()
    user = models.ForeignKey(User,on_delete=models.PROTECT)
    signed_challenge = models.TextField(blank=True)
