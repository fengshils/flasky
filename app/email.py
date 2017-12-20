from flask_mail import Message
from flask import render_template, current_app
from app import mail, DevelopmentConfig
from threading import Thread


FLASKY_MAIL_SUBJECT_PREFIX = 'Flasky'

def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)



def send_email(to, subject, template, **kwargs):
    app = current_app._get_current_object() 
    msg = Message(FLASKY_MAIL_SUBJECT_PREFIX + subject, 
                  sender=DevelopmentConfig.FLASKY_MAIL_SENDER, recipients=[to]) 
    msg.body = render_template(template + '.txt', **kwargs) 
    msg.html = render_template(template + '.html', **kwargs) 
    thr = Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr