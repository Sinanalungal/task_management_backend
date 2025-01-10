import random
from django.core.mail import send_mail
from django.conf import settings

def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_otp_email(email, otp):
    subject = 'Verify Your Email'
    message = f'Your OTP for registration is: {otp}\nThis OTP is valid for 10 minutes.'
    from_email =  settings.DEFAULT_FROM_EMAIL 
    recipient_list = [email]
    
    send_mail(subject, message, from_email, recipient_list)
