from django.urls import path
from .views import *

urlpatterns = [
    path('', home, name="homepage"),
    path('signup/', signupuser, name="signuppage"),
    path('verify/<auth_token>', verify, name="verify"),
    path('error/', error_page, name="errorpage"),
    path('login/', loginuser, name="loginpage"),
    path('logout/', logoutuser, name='logoutuser'), 
    path('sendmail/', sendmailview, name="sendmailpage"),
    path('mailsent/', mailsentview, name="mailsentpage"),
    path('resetpswd/<auth_token>', resetpswdview, name="resetpswdpg"),
    path('upload/', upload, name='uploadpage'),
    path('share/<int:upload_id>', share, name='sharepage'),
    path('editupload/<int:upload_pk>', editupload, name='edituploadpg'),
    path('editshare/<int:share_pk>', editshare, name='editsharepg'),
    path('deleteupload/<int:upload_pk>', deleteupload, name='deleteupload'),
    path('deleteshare/<int:share_pk>', deleteshare, name='deleteshare'),
]