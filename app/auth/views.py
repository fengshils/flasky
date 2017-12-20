from flask import render_template, redirect, request, url_for, flash
from flask_login import login_required, login_user, logout_user, current_user
from app import db
from . import auth
from ..models import User
from .forms import LoginForm, RegistrationForm
from app.email import send_email

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        print(form.email.data, form.password.data)
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('main.index')
            return redirect(next)
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/logout/')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                username=form.username.data,
                password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account',
                    'auth/email/confirm', user=user, token=token)
        flash('确认邮件已经发送到您的邮箱。')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>/')
@login_required
def  confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('您的账户已经激活，Thanks！')
    else:
        flash('此确认链接已经失效，或者过期')
    return redirect(url_for('main.index'))

"""
同时满足以下 3 个条件时，before_app_request 处理程序会拦截请求。
(1) 用户已登录（current_user.is_authenticated() 必须返回 True） 。
(2) 用户的账户还未确认。
(3) 请求的端点（使用 request.endpoint 获取）不在认证蓝本中。访问认证路由要获取权
限，因为这些路由的作用是让用户确认账户或执行其他账户管理操作。
如果请求满足以上 3 个条件，则会被重定向到 /auth/unconfirmed 路由，显示一个确认账户
相关信息的页面。
"""

@auth.before_app_request
def before_request():
    if current_user.is_authenticated() and not current_user.confirmed and request.endpoint[:5] != 'auth.' and request.endpoint != 'static':
        return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed/')
def unconfirmed():
    if current_user.is_anonymous() or current_user.confirmed:
        return(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


#重新发送确认邮件
@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token() 
    send_email(current_user.email, 'Confirm Your Account', 
               'auth/email/confirm', user=current_user, token=token) 
    flash('确认邮件已经重新发送，请注意查收！') 
    return redirect(url_for('main.index'))

@auth.route('/secret/')
@login_required
def secret():
    return 'Only authenicated users are allowed!'