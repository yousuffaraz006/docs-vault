from django.db import models
from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    auth_token = models.CharField(max_length=100, null=True, blank=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username
    
class Upload(models.Model):
    title = models.CharField(max_length=100)
    created = models.DateTimeField(auto_now_add=True)
    docimg = models.ImageField(upload_to='locker/images/')
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.title
    
class Share(models.Model):
    sender_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sender')
    reciever_user = models.ForeignKey(User, on_delete=models.CASCADE)
    shrdtitle = models.CharField(max_length=100)
    shrdimg = models.ImageField(upload_to='locker/images/')
    dwnldprms = models.BooleanField(default=False)
    shrdtime = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.sender_user)