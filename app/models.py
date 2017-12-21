from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from . import login_manager
from flask_login import UserMixin, AnonymousUserMixin
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request
from datetime import datetime
import hashlib 
from markdown import markdown
import bleach

#使用8进制表示，次数使用五位，预留三位
class Permission:
    """
    只有一个角色的 default 字段要设为 True，其他都设为 False。用户注册时，其角色会被
设为默认角色。
这个模型的第二处改动是添加了 permissions 字段，其值是一个整数，表示位标志。各操
作都对应一个位位置，能执行某项操作的角色，其位会被设为 1。
    """
    FOLLOW = 0x01           #关注其他用户
    COMMENT = 0x02          #在他人撰写的文章中发布评论
    WRITE_ARTICLES = 0x04   #写原创文章
    MODERATE_COMMENTS = 0x08         #查处他人发表的不当评论
    ADMINISTER = 0x80       #管理网站

class Role(db.Model): 
    __tablename__ = 'roles' 
    id = db.Column(db.Integer, primary_key=True) 
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic') 
 
    """
    匿名      0b00000000（0x00） 未登录的用户。在程序中只有阅读权限
    用户      0b00000111（0x07） 具有发布文章、发表评论和关注其他用户的权限。这是新用户的默认角色
    协管员    0b00001111（0x0f） 增加审查不当评论的权限
    管理员    0b11111111（0xff） 具有所有权限，包括修改其他用户所属角色的权限
    使用权限组织角色，这一做法让你以后添加新角色时只需使用不同的权限组合即可
    函数并不直接创建新角色对象，而是通过角色名查找现有的角色，然后再
    进行更新。只有当数据库中没有某个角色名时才会创建新角色对象。如此一来，如果以后
    更新了角色列表，就可以执行更新操作了。要想添加新角色，或者修改角色的权限，修改
    roles 数组，再运行函数即可。注意， “匿名”角色不需要在数据库中表示出来，这个角色
    的作用就是为了表示不在数据库中的用户。
    """
    @staticmethod 
    def insert_roles(): 
        roles = { 
            'User': (Permission.FOLLOW | 
                     Permission.COMMENT | 
                     Permission.WRITE_ARTICLES, True), 
            'Moderator': (Permission.FOLLOW | 
                          Permission.COMMENT | 
                          Permission.WRITE_ARTICLES | 
                          Permission.MODERATE_COMMENTS, False), 
            'Administrator': (0xff, False) 
        } 
        for r in roles: 
            role = Role.query.filter_by(name=r).first() 
            if role is None: 
                role = Role(name=r) 
            role.permissions = roles[r][0] 
            role.default = roles[r][1] 
            db.session.add(role) 
        db.session.commit()

    def __repr__(self): 
        return '<Role %r>' % self.name 
 
class User(UserMixin, db.Model): 
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
    __tablename__ = 'users' 
    id = db.Column(db.Integer, primary_key=True)
    email =  db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True) 
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    name = db.Column(db.String(64))                                         #真实姓名
    location = db.Column(db.String(64))                                     #所在地
    about_me = db.Column(db.Text())                                         #自我介绍
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)        #注册日期
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)           #最后访问日期
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    #User 类的构造函数首先调用基类的构造函数，如果创建基类对象后还没定义角色，则根据电子邮件地址决定将其设为管理员还是默认角色
    def __init__(self, **kwargs): 
        super(User, self).__init__(**kwargs)
        if self.role is None: 
            if self.email == current_app.config['FLASKY_ADMIN']: 
                self.role = Role.query.filter_by(permissions=0xff).first() 
            if self.role is None: 
                self.role = Role.query.filter_by(default=True).first()
 
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
    
    #更新用户最后登录时间
    def ping(self): 
        self.last_seen = datetime.utcnow() 
        db.session.add(self)
    
    def __repr__(self): 
        return '<User %r>' % self.username
    
    #判断用户角色权限
    def can(self, permissions): 
        return self.role is not None and  (self.role.permissions & permissions) == permissions 
 
    def is_administrator(self): 
        return self.can(Permission.ADMINISTER) 

    avatar_hash = db.Column(db.String(32)) 
 
    def __init__(self, **kwargs): 
        # ... 
        if self.email is not None and self.avatar_hash is None: 
            self.avatar_hash = hashlib.md5( 
                self.email.encode('utf-8')).hexdigest() 
 
    def change_email(self, token): 
        # ... 
        self.email = new_email 
        self.avatar_hash = hashlib.md5( 
            self.email.encode('utf-8')).hexdigest() 
        db.session.add(self) 
        return True 
 
    def gravatar(self, size=100, default='identicon', rating='g'): 
        if request.is_secure: 
            url = 'https://secure.gravatar.com/avatar' 
        else: 
            url = 'http://www.gravatar.com/avatar' 
        hash = self.avatar_hash or hashlib.md5( 
            self.email.encode('utf-8')).hexdigest() 
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format( 
            url=url, hash=hash, size=size, default=default, rating=rating)



class AnonymousUser(AnonymousUserMixin): 
    def can(self, permissions): 
        return False 
 
    def is_administrator(self): 
        return False 
 
login_manager.anonymous_user = AnonymousUser

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#文章模型
class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    """on_changed_body 函数注册在 body 字段上，是 SQLAlchemy“set”事件的监听程序，这意
    味着只要这个类实例的 body 字段设了新值，函数就会自动被调用。on_changed_body 函数
    把 body 字段中的文本渲染成 HTML 格式，结果保存在 body_html 中，自动且高效地完成
    Markdown 文本到 HTML 的转换
    """
    @staticmethod
    def  on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul', 
                        'h1', 'h2', 'h3', 'p'] 
        target.body_html = bleach.linkify(bleach.clean( 
            markdown(value, output_format='html'), 
            tags=allowed_tags, strip=True)) 
 
db.event.listen(Post.body, 'set', Post.on_changed_body)
