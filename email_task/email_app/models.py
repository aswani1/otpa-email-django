from django.db import models

# Create your models here.
class otp(models.Model):
    otp_id = models.CharField(max_length=200)
