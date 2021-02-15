# -*- coding: UTF-8 -*-
from werkzeug.security import generate_password_hash,check_password_hash
from . import login_manager
from flask_login import UserMixin,AnonymousUserMixin
from flask_login import login_required
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app
from . import db
from datetime import datetime
import hashlib
from flask import request
from markdown import markdown
import bleach

'''关注者模型'''
class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer,
                            db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer,
                            db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime,default=datetime.utcnow)

'''博客文章模型'''
class Post(db.Model):
    __tablename__ = 'posts'   #定义在数据库中使用的表名

    id = db.Column(db.Integer,primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime,index=True,default=datetime.utcnow)
    author_id = db.Column(db.Integer,db.ForeignKey('users.id'))
    body_html = db.Column(db.Text)

    @staticmethod
    def on_change_body(target,value,oldvalue,initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(              #linkigy()函数将文本中的URL转换为合适的链接
            bleach.clean(                               #clean()函数删除所有不在白名单中的标签
                markdown(value,output_format='html'),   #初步将纯文本转化为html
                tags=allowed_tags,                      #html标签白名单
                strip=True
        ))
db.event.listen(Post.body,'set',Post.on_change_body)  #将on_change_body注册到Post的body字段上  PS.126

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64),unique=False)
    #users属性返回的是一个User的列表对象
    users = db.relationship('User',backref='role',lazy='dynamic') # backref相当于一个回调函数，替代了User类中的role_id PS.50,51
    default = db.Column(db.Boolean,default=False,index=True)
    permissions = db.Column(db.Integer)

    def __init__(self,**kwargs):
        super(Role,self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    '''这是一个静态方法，定义了角色的名称属性'''
    @staticmethod
    def insert_roles():
        roles = {
            'User':[Permission.FOLLOW,Permission.COMMENT,Permission.WRITE],
            'Moderator':[Permission.FOLLOW,Permission.COMMENT,Permission.WRITE,Permission.MODERATE],
            'Administrator':[Permission.FOLLOW,Permission.COMMENT,Permission.WRITE,Permission.MODERATE,Permission.ADMIN]
        }
        default_role = 'User'  # 默认角色为User
        for r in roles:
            role = Role.query.filter_by(name=r).first()  # 从角色表中查找角色名称为 r 的角色，如果没有这个角色，就创建一个
            if role is None:
                role = Role(name=r)
            role.reset_permissions()  # 这个角色名称 有着一个列表的权限值，先重置为0，再将表中的权限值相加
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)  # 是否为默认角色
            db.session.add(role)
        db.session.commit() # 这个函数运行结束，就已经完成了对所有角色名称权限的赋值，然后提交

    def has_permission(self, perm):
        return self.permissions & perm == perm  #判断当前角色是否存在这个权限
    def add_permission(self,perm):
        if not self.has_permission(perm):
            self.permissions += perm
    def remove_permission(self,perm):
        if self.has_permission(perm):
            self.permissions -= perm
    def reset_permissions(self):
        self.permissions = 0

    def __repr__(self):
        return '<Role %r>' % self.name  #返回易读的字符串，供测试用

class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16

'''这个类用于让应用的登录状态和未登录状态能调用同样的函数'''
class AnonymousUser(AnonymousUserMixin):
    def can(self,permission): # 由于当前已确定用户处于未登录状态，所以都返回False
        return False
    def is_administrator(self):
        return False
login_manager.anonymous_user = AnonymousUser  #ps.101 login_manager 是一个外部类的实例

class User(UserMixin,db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer,primary_key=True) #这个键的类型为integer,主键id，
    username = db.Column(db.String(64),unique=True,index=True)  # 64字节的长度，不能重复，创建索引， 列类型，PS.48
    role_id = db.Column(db.Integer,db.ForeignKey('roles.id'))  #关系 名为 roles 的表的 id 列为外键
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(64),unique=True,index=True)
    confirmed = db.Column(db.Boolean,default=False)
    name = db.Column(db.String(64))      #真实姓名
    location = db.Column(db.String(64))  #真实地址
    about_me = db.Column(db.Text())      #简介
    member_since = db.Column(db.DateTime(),default=datetime.utcnow)#注册日期
    last_seen = db.Column(db.DateTime(),default=datetime.utcnow)#最后一次登录时间
    posts = db.relationship('Post',backref='author',lazy='dynamic')  #这是对于Post表的父表，
    avatar_hash = db.Column(db.String(64))
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower',lazy='joined'),
                               lazy='dynamic',
                               cascade='all,delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed',lazy='joined'),
                                lazy='dynamic',
                                cascade='all,delete-orphan')
    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()
    @property
    def followed_posts(self):
        return Post.query.join(Follow,Follow.followed_id==Post.author_id).filter(Follow.follower_id==self.id)

    '''只要调用这个User类，就会执行初始化，开始检查用户是否已经被赋予角色名称，检查用户的邮箱是否为管理员邮箱，若不是，则赋予用户角色名称为User'''
    def __init__(self,**kwargs):
        super(User,self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            else:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash() # 这里的self.avatar_hash 和 avatar_hash 是一样的，之前定义了模型，现在赋予了初值

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)
        db.session.commit()

    def can(self, perm): #确定已登录用户是否具有某项权限
        return self.role is not None and self.role.has_permission(perm)
    def is_administrator(self): #判断当前用户是否具有管理员权限
        return self.can(Permission.ADMIN)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    # def __repr__(self):
    #     return '<User %r>' % self.username

    '''产生一个签名'''
    def generate_confirmation_token(self,expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'],expiration) # s 是一个对象
        return s.dumps({'confirm':self.id}).decode('utf-8')   #这里不应该使用用户id加载签名，因为在加载签名时已经将新用户添加到数据库中了

    '''调用这个函数用于解析签名'''
    def confirm(self,token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except :
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self,expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'],expiration)
        return s.dumps({'reset':self.id}).decode('utf-8')

    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self,expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'],expiration)
        return s.dumps({'change_email': self.id}).decode('utf-8')

    @staticmethod
    def change_email(token,new_email):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        user = User.query.get(data.get('change_email'))
        if data.get('change_email') != user.id:
            return False
        if new_email is None:
            return False
        if User.query.filter_by(email=new_email).first() is not None:
            return False
        user.email = new_email
        db.session.add(user)
        return True

    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode('utf-8')).hexdigest()
    #计算头像散列值最后链接
    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or self.gravatar_hash()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(url=url, hash=hash, size=size, default=default,rating=rating)

    def follow(self,user):
        if not self.is_following(user):
            f = Follow(follower=self,followed=user)
            db.session.add(f)
    def unfollow(self,user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)
    def is_following(self,user):
        if user.id is None:
            return False
        return self.followed.filter_by(followed_id=user.id).first() is not None
    def is_followed_by(self,user):
        if user.id is None:
            return False
        return self.followers.filter_by(follower_id=user.id).first() is not None

'''正常情况下根据用户id返回用户对象，若发生错误则返回None'''
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

    # @app.route('/secret')
    # @login_required
    # def secret(self):
    #     return 'Only authenticated users are allowed!'
