from flask_wtf import FlaskForm
from  wtforms import StringField, PasswordField, BooleanField, SubmitField 
from wtforms.validators import DataRequired, Length, Email, Length, Regexp,EqualTo
from wtforms import ValidationError
from app.models import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64),
                                             Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

"""
这个表单使用 WTForms 提供的 Regexp 验证函数，确保 username 字段只包含字母、数字、
下划线和点号。这个验证函数中正则表达式后面的两个参数分别是正则表达式的旗标和验
证失败时显示的错误消息。
安全起见，密码要输入两次。此时要验证两个密码字段中的值是否一致，这种验证可使用
WTForms 提供的另一验证函数实现，即 EqualTo。这个验证函数要附属到两个密码字段中
的一个上，另一个字段则作为参数传入。
这个表单还有两个自定义的验证函数，以方法的形式实现。如果表单类中定义了以
validate_ 开头且后面跟着字段名的方法，这个方法就和常规的验证函数一起调用。本例
分别为 email 和 username 字段定义了验证函数，确保填写的值在数据库中没出现过。自定
义的验证函数要想表示验证失败，可以抛出 ValidationError 异常，其参数就是错误消息。
"""

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(1, 64), 
                                             Email()]) 
    username = StringField('Username', validators=[ 
        DataRequired(), Length(1, 64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 
                                          'Usernames must have only letters, ' 
                                          'numbers, dots or underscores')]) 
    password = PasswordField('Password', validators=[ 
        DataRequired(), EqualTo('password2', message='Passwords must match.')]) 
    password2 = PasswordField('Confirm password', validators=[DataRequired()]) 
    submit = SubmitField('Register') 
 
    def validate_email(self, field): 
        if User.query.filter_by(email=field.data).first(): 
            raise ValidationError('Email already registered.') 
 
    def validate_username(self, field): 
        if User.query.filter_by(username=field.data).first(): 
            raise ValidationError('Username already in use.')
    