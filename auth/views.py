# -*- coding: UTF-8 -*-
from flask import  render_template,redirect,request,url_for,flash,current_app
from flask_login import login_user,login_required,logout_user,current_user
from . import auth
from ..models import User
from .forms import LoginForm,RegistrationForm,ChangePasswordForm,PasswordResetForm,\
    PasswordResetRequestForm,ChangeEmailForm
from .. import db
from ..email import send_email

@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed and request.endpoint and request.blueprint != 'auth' and request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))

@auth.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user,form.remeber_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('无效密码或用户名')
    return render_template('auth/login.html',form=form)

@auth.route('/reset',methods=['GET','POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user :
            token = user.generate_reset_token()
            send_email(form.email,'你正在重设密码','auth/email/reset_password',user=user,token=token)
        flash('已发送邮件到你的邮箱')
        return redirect(url_for('auth.login'))
    return render_template('auth/password_reset_request.html',form=form)

@auth.route('/reset/<token>',methods=['GET','POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        if User.reset_password(token,form.password.data):
            db.session.commit()
            flash('密码已重设')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/password_reset_request.html',form=form)

@auth.route('/change_password',methods=['GET','POST'])
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash('Your password has been updated.')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password.')
    return render_template("auth/change_password.html", form=form)


'''邮箱修改有点问题，只要确认是本人在修改，就能修改为任意邮箱，若此邮箱不是自己的邮箱，则之后无法修改，'''
@auth.route('/change_email_request',methods=['GET','POST'])
@login_required
def change_email_request():
    next = request.args.get('next')
    if next is None or not next.startswith('/'):
        next = url_for('main.index')
    token = current_user.generate_email_change_token()
    send_email(current_user.email,'验证你的邮箱','auth/email/change_email',user=current_user,token=token)
    return redirect(next)   #到当前也页面
@auth.route('/change_email/<token>',methods=['GET','POST'])
def change_email(token):
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.change_email(token,form.email.data):
            db.session.commit()
            flash('邮箱修改成功')
            return redirect(url_for('main.index'))
        else:
            flash('邮箱修改失败')
    return render_template('auth/change_email_request.html',form=form)

@auth.route('/register',methods=['GET','POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()  #获取加密签名之前已经将用户信息加载到数据库了，那签名实际上就没有用了，
                                                    # 原因是，这种签名的加密过程用到了用户id，所以需要先提交，之后写一个自定义的签名加密方式，就不需要先提交了
        send_email(user.email, 'please confirm you account', 'auth/email/confirm', user=user,token=token)
        flash('a confirm email has been send to you by email')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html',form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('已退出')
    return redirect(url_for('main.index'))

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:  #这里的confirmed是User的属性
        return redirect(url_for('main.index'))
    if current_user.confirm(token):  # 这里的confirm是User的方法
        db.session.commit()
        flash('you have confirmed you account,thanks')
    else:
        flash('the confirmation link is incalid or has expired')
    return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
    if current_user.is_authenticated and not current_user.confirmed and request.blueprint != 'auth' and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')

@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email,'Confirm you account','auth/email/confirm',user=current_user,token=token)
    flash('A new confirmation email has been send to you by email')
    return redirect(url_for('main.index'))



