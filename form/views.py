from email.message import EmailMessage
from lib2to3.pgen2.tokenize import generate_tokens
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib  import messages
from django.contrib.auth import authenticate, login, logout
from conda1 import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token
from .models import Members


# Create your views here.
def home(request):
    return render(request,"form/index.html")

def signup(request):
    #take the inputs from the user

    if request.method == "POST":
        #username = request.POST['username']
        username = request.POST.get('username')
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        password = request.POST.get('pass1')
        password2 = request.POST.get('pass2')

        #validations if the username already exists in the DB then user won't be able to create another account
        if User.objects.filter(username = username):
            messages.error(request,'Username already exists!! Please try another username')
            return redirect('home')

        #validate the email if it exists don't register the user
        if User.objects.filter(email = email):
            messages.error(request, 'The Email already exists!!')
            return redirect('home')

        #length of the username should not be longer than 10
        if len(username) > 10:
            messages.error(request, 'username should be less than 10 characters')

        #if password does not match confirm password
        if  password != password2:
            messages.error(request, 'Passwords do not match! Try again!!')

        #username should be alphanumeric
        if not username.isalnum:
            messages.error(request, 'username must contain only letters and numbers')
            return redirect('home')



        #save the inputs in the database
        myuser = User.objects.create_user(username,email, password)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False

        myuser.save()

        #message for a successful creation of account
        
        messages.success(request, 'Logged in successfully')

        #the sending welcome emails function
        subject = "Welcome to Tels Login!!"
        message = 'Hi ' + myuser.first_name + ' ,\n' + 'Welcome to Tels\n Thank you for visting our website \n we have sent you a confirmation email, please confirm your email address to activate your account\n\n Thank you, Andemoli.' 
        from_email = settings.EMAIL_HOST_USER
        to_people=[myuser.email]
        send_mail(subject,message, from_email,to_people, fail_silently = True)

        #email address confirmation 
        current_site = get_current_site(request)
        email_subject = 'Confirm your email @fgg -django login'
        message2 = render_to_string('email_confirmation.html', {'name':myuser.first_name,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
        'token': generate_token.make_token(myuser),})

        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],

        )
        email.fail_silently = True
        email.send()
        



        #direct the user to the signin page
        return redirect('signin')




    return render(request, "form/signup.html")

def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['pass1']

        #authenticate the user
        user = authenticate(username =username, password = password)
        if user is not None:
            #return a none user if user not authenticated
            login(request, user)
            fname = user.first_name
            return render(request, 'form/index.html', {'fname': fname})

        #if credentials are bad tell the user
        else: 
            messages.error(request,"Bad credentials!!")
            
            return redirect('home')


    return render(request, "form/signin.html")

def signout(request):
    logout(request)
    messages.success(request, 'Logged out successfully')
    return redirect('home')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk = uid)

    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token .check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect ("home")

    else:
        return render(request, 'failed.html')

