from django.forms import ModelForm
from .models import Upload, Share

class UploadForm(ModelForm):
    class Meta:
        model = Upload
        fields = ['title', 'docimg']

class ShareForm(ModelForm):
    class Meta:
        model = Share
        fields = ['reciever_user', 'shrdtitle', 'shrdimg', 'dwnldprms']