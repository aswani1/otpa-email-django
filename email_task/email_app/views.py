from django.shortcuts import render
from django.contrib.auth.models import User
# Create your views here.
from random import randint
from django.http import *
from django.shortcuts import render_to_response,redirect
from django.template import RequestContext
from .models import *
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm
from django.core.mail import send_mail
from django.conf import settings

def login_user(request):
    ''' login system function '''
    logout(request)
    username = password = ''
    if request.POST:
        username = request.POST['username']
        password = request.POST['password']
        
        def random_with_N_digits(n):
            range_start = 10**(n-1)
            range_end = (10**n)-1
            return randint(range_start, range_end)

        

        user = authenticate(username=username, password=password)
        
        try:
            check_r = random_with_N_digits(4)
            usr = User.objects.get(username=username)
            
            if password == usr.password:
                subject = 'one time password'
                message = str(check_r)
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [username,]
                send_mail( subject, message, email_from, recipient_list )
                otp.objects.create(otp_id=check_r)
                return HttpResponseRedirect('/otp/')
        except:
            return HttpResponseRedirect('/signup/')
    return render(request,'registration/login.html',{})

def signup(request):
    ''' sighn up function '''
    if request.method == 'POST':
        
        username = request.POST['username']
        raw_password = request.POST['password']
        User.objects.create(username=username,password=(raw_password))
        return redirect('/login/')
    return render(request, 'registration/regi.html',{})

def otp_check(request):
    ''' otp checking function '''
    if request.POST:
        otp1 = request.POST['otp']
        try:
            otp.objects.get(otp_id=otp1)
            return redirect('thank')
        except:
            return redirect('/login')

    return render(request,'registration/otp.html',{})

def thank(request):
    ''' thank you '''
    return render(request,'registration/thank.html',{})