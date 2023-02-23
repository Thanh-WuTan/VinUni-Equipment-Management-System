from email.message import EmailMessage
import ssl
import smtplib
import string
import secrets
import random

def generate_password():
    letters = ''
    for c in range(26):
        if (chr(c + ord('a')) != 'l'):
            letters+= chr(c + ord('a'))
        if (chr(c + ord('A')) != 'I'):
            letters+= chr(c + ord('A'))    
    digits = string.digits
    special_chars = '$@#%&'
    alphabet = letters + digits
    password = ''
    for i in range(2):
        password+= ''.join(secrets.choice(special_chars))
    for i in range(8):
        password+= ''.join(secrets.choice(alphabet))    
    return password
    

def send_password(email_receiver, password, subject):
    email_sender = 'wt.vathanh@gmail.com'
    email_password = 'jwsaptylkyjkzayx'
    body = """
    Here is your password : {fpassword}
    """.format(fpassword = password)
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context = context) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())