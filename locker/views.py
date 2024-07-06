from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.contrib import messages
from django.conf import settings
from .decorators import unauthenticated_user
from DigilockerProj.settings import DEBUG
from .models import *
from .forms import *
import uuid

# Modified
@unauthenticated_user
def signupuser(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        firstname = request.POST.get('first_name')
        lastname = request.POST.get('last_name')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        user_exist = User.objects.filter(username=username).first()
        if user_exist:
            messages.info(request, 'Username has already been taken.')
            return redirect('signuppage')
        elif password1 != password2:
            messages.info(request, 'Passwords did not match.')
            return redirect('signuppage')
        else:
            user_obj = User.objects.create_user(username, first_name=firstname, last_name=lastname, password=password1)
            auth_token = str(uuid.uuid4())
            profile_obj = Profile.objects.create(user=user_obj, auth_token=auth_token)
            profile_obj.save()
            send_mail_after_registration(username, auth_token)
            messages.info(request, f'Account has been created for Mr. {user_obj.first_name}. Please check your email to verify your account.')
            return redirect('loginpage')
    return render(request, 'locker/signuppage.html')

def send_mail_after_registration(email, token):
    user_fname = User.objects.get(username=email).first_name
    if DEBUG:
        link = '127.0.0.1:8000'
    else:
        link = 'https://yousufaraz.pythonanywhere.com'
    subject = 'Account Verification'
    message = f'Hi {user_fname}, please click on the link to verify your account on Desi Digilocker. {link}/verify/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)

def verify(request, auth_token):
    try:
        profile_obj = Profile.objects.filter(auth_token=auth_token).first()
        if profile_obj:
            if profile_obj.is_verified:
                messages.info(request, 'Your account is already verified.')
                return redirect('loginpage')
            else:
                profile_obj.is_verified = True
                profile_obj.auth_token = ''
                profile_obj.save()
                messages.info(request, 'Your account has been verified.')
                return redirect('loginpage')
        else:
            return redirect('errorpage')
    except Exception as e:
        print(e)
        return render(request, 'locker/signuppage.html')

@unauthenticated_user
def error_page(request):
    return render(request, 'locker/errorpage.html')

@unauthenticated_user
def loginuser(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user_obj = User.objects.filter(username=username).first()
        if user_obj is None:
            messages.info(request, 'User not found.')
            return redirect('loginpage')
        else:
            profile_obj = Profile.objects.filter(user=user_obj).first()
            if not profile_obj.is_verified:
                auth_token = str(uuid.uuid4())
                profile_obj.auth_token = auth_token
                profile_obj.save()
                email_obj = User.objects.get(username=username).username
                send_mail_after_registration(email_obj, auth_token)
                messages.info(request, 'Your account is not verified. Please check your mailbox for "Account Verification" mail and click on the link to verify your account. We have sent a new "Account Verification" mail.')
                return redirect('loginpage')
            else:
                user = authenticate(username=username, password=password)
                if user is None:
                    messages.info(request, 'Please enter the credentials correctly.')
                    return redirect('loginpage')
                else:
                    login(request, user)
                    return redirect('homepage')
    else:
        return render(request, 'locker/loginpage.html')
    
@unauthenticated_user
def sendmailview(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        user_obj = User.objects.filter(username=username).first()
        if user_obj:
            auth_token = str(uuid.uuid4())
            profile_obj = Profile.objects.get(user=user_obj)
            if profile_obj.is_verified:
                profile_obj.auth_token = auth_token
                profile_obj.save()
                send_mail_for_reset(username, auth_token)
                return redirect('mailsentpage')
            else:
                profile_obj.auth_token = auth_token
                profile_obj.save()
                username_obj = User.objects.get(username=user_obj.username).username
                send_mail_after_registration(username_obj, auth_token)
                messages.info(request, 'Your account is not verified. Please check your mailbox for "Account Verification" mail and click on the link to verify your account. We have sent a new "Account Verification" mail.')
                return redirect('loginpage')
        else: 
            messages.info(request, 'User not found.')
            return redirect('sendmailpage')
    else:
        return render(request, 'locker/sendmailpage.html')

def send_mail_for_reset(email, token):
    user_fname = User.objects.get(username=email).first_name
    if DEBUG:
        link = '127.0.0.1:8000'
    else:
        link = 'https://yousufaraz.pythonanywhere.com'
    subject = 'Password Reset'
    message = f'Hi {user_fname}, please click on the link to reset your account password on Desi Digilocker. {link}/resetpswd/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)

@unauthenticated_user
def mailsentview(request):
    return render(request, 'locker/mailsentpage.html')

@unauthenticated_user
def resetpswdview(request, auth_token):
    if request.method == 'POST':
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        if password1 == password2:
            profile_obj = Profile.objects.filter(auth_token=auth_token).first()
            if profile_obj:
                user_obj = profile_obj.user
                user_obj.set_password(password1)
                user_obj.save()
                profile_obj.auth_token = ''  # Clear the auth token
                profile_obj.save()
                messages.info(request, 'Your password has been reset successfully.')
                return redirect('loginpage')
            else:
                messages.info(request, 'Invalid token.')
                return redirect('resetpassword')
        else:
            messages.info(request, 'Passwords did not match.')
            return redirect('resetpswdpg')
    else:
        return render(request, 'locker/resetpswdpg.html', {'auth_token': auth_token})

def logoutuser(request): 
    logout(request)
    return redirect('loginpage') 
    
@login_required(login_url="/login")
def home(request):
    shares = Share.objects.all().order_by('-shrdtime')
    profile = Profile.objects.get(user=request.user)
    uploads = Upload.objects.filter(user=request.user).order_by('-created')
    return render(request, 'locker/homepage.html', {'uploads':uploads, 'profile':profile, 'shares':shares})

@login_required(login_url="/login")
def upload(request):
    if request.method == 'POST':
        try:
            form = UploadForm(request.POST, request.FILES)
            newupload = form.save(commit=False)
            newupload.user = request.user
            newupload.save()
            return redirect('homepage')
        except ValueError:
            messages.info(request, 'Error : Bad data passed in. Try again.')
            return redirect('uploadpage')
    else:
        return render(request, 'locker/uploadpage.html', {'form':UploadForm})
    
@login_required(login_url="/login")
def share(request):
    alluser = User.objects.all().exclude(username=request.user)
    if request.method == 'POST':
        try:
            form = ShareForm(request.POST, request.FILES)
            newshare = form.save(commit=False)
            newshare.sender_user = request.user
            newshare.save()
            return redirect('homepage')
        except ValueError:
            messages.info(request, 'Error : Bad data passed in. Try again.')
            return redirect('sharepage')
    else:
        return render(request, 'locker/sharepage.html', {'form':UploadForm, 'alluser':alluser})

@login_required(login_url="/login")
def editupload(request, upload_pk):
    upload = get_object_or_404(Upload, pk=upload_pk, user=request.user)
    if request.method == 'POST':
        try:
            form = UploadForm(request.POST, request.FILES, instance=upload)
            form.save()
            return redirect('homepage')
        except ValueError:
            messages.info(request, 'Error : Bad info')
            return redirect('edituploadpg', upload_pk=upload_pk)
    else:
        form = UploadForm(instance=upload)
        return render(request, 'locker/edituploadpg.html', {'upload':upload, 'form':form})

@login_required(login_url="/login")
def editshare(request, share_pk):
    share = get_object_or_404(Share, pk=share_pk, sender_user=request.user)
    alluser = User.objects.all().exclude(username=request.user).exclude(username=share.reciever_user.username)
    if request.method == 'POST':
        try:
            form = ShareForm(request.POST, request.FILES, instance=share)
            form.save()
            return redirect('homepage')
        except ValueError:
            messages.info(request, 'Error : Bad info')
            return redirect('editsharepg', share_pk=share_pk)
    else:
        form = ShareForm(instance=share)
        return render(request, 'locker/editsharepg.html', {'share':share, 'form':form, 'alluser':alluser}) 
        
@login_required(login_url="/login")
def deleteupload(request, upload_pk):
    upload = get_object_or_404(Upload, pk=upload_pk, user=request.user)
    if request.method == 'POST':
        upload.delete()
        return redirect('homepage')
        
@login_required(login_url="/login")
def deleteshare(request, share_pk):
    share = get_object_or_404(Share, pk=share_pk, sender_user=request.user)
    if request.method == 'POST':
        share.delete()
        return redirect('homepage')