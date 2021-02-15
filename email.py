# -*- coding: UTF-8 -*-

from flask_mail import Message
from flask import render_template,current_app
from threading import Thread
from . import mail

'''异步发送电子邮件'''
def send_async_email(app,msg):
    with app.app_context():  #通过调用 app.app_context() 激活应用上下文
        mail.send(msg)

'''这是个集成邮件到应用中的函数'''
def send_email(to,subject,template,**kwargs):
    #send_email（收信人，邮件头部，正文）
    app = current_app._get_current_object()
    msg = Message(app.config['FLASKY_MAIL_SUBJECT_PREFIX'] + subject,sender=app.config['FLASKY_MAIL_SENDER'],recipients=[to])# Message(邮件头部，寄信人，收信人）
    msg.body = render_template(template + '.txt',**kwargs)
    msg.html = render_template(template + '.html',**kwargs)   # 邮件正文
    thr = Thread(target=send_async_email,args=[app,msg])  #启用线程，传入目标函数，和函数参数  菜鸟教程 https://www.runoob.com/python/python-multithreading.html
    # 这里应该有一个消息队列，目前应该还是单线程的，应该改进
    thr.start()
    return thr