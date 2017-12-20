from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from . import login_manager
from flask_login import UserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app

"""
Werkzeug 中的 security 模块能够很方便地实现密码散列值的计算。这一功能的实现只需要
两个函数，分别用在注册用户和验证用户阶段。
generate_password_hash(password, method=pbkdf2:sha1, salt_length=8)：这个函数将
原始密码作为输入， 以字符串形式输出密码的散列值， 输出的值可保存在用户数据库中。
method 和 salt_length 的默认值就能满足大多数需求。
check_password_hash(hash, password)：这个函数的参数是从数据库中取回的密码散列
值和用户输入的密码。返回值为 True 表明密码正确。

itsdangerous 提供了多种生成令牌的方法。其中，TimedJSONWebSignatureSerializer 类生成
具有过期时间的 JSON Web 签名（JSON Web Signatures，JWS） 。这个类的构造函数接收
的参数是一个密钥，在 Flask 程序中可使用 SECRET_KEY 设置。
dumps() 方法为指定的数据生成一个加密签名，然后再对数据和签名进行序列化，生成令
牌字符串。expires_in 参数设置令牌的过期时间，单位为秒。
为了解码令牌，序列化对象提供了 loads() 方法，其唯一的参数是令牌字符串。这个方法
会检验签名和过期时间，如果通过，返回原始数据。如果提供给 loads() 方法的令牌不正
确或过期了，则抛出异常
"""

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Role(db.Model): 
    __tablename__ = 'roles' 
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role') 
 
    def __repr__(self): 
        return '<Role %r>' % self.name 
 
class User(UserMixin, db.Model): 
    __tablename__ = 'users' 
    id = db.Column(db.Integer, primary_key=True)
    email =  db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True) 
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
 
    @property
    def password(self):
        raise AttributeError('password is not readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') !=self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def __repr__(self): 
        return '<User %r>' % self.username