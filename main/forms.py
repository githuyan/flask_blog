# -*- coding: UTF-8 -*-
from flask_wtf import FlaskForm # flask_wtf 为一个处理web表单的 flask扩展
from wtforms import StringField,SubmitField,TextAreaField,BooleanField,SelectField
from wtforms.validators import DataRequired,Length,Email,Regexp,ValidationError
from ..models import Role,User
from flask_pagedown.fields import PageDownField

'''表单类，字段信息包括，name，submit，前面从flask_wtf导入的有处理这些字段的类'''
class NameForm(FlaskForm):
    # 这些变量均为类变量
    name = StringField('你的名字？',validators=[DataRequired()]) # validators 为一个可选验证函数列表，PS.36
    submit = SubmitField('Submit')

class EditProfileForm(FlaskForm):
    name = StringField('Real name', validators=[Length(0, 64)])
    location = StringField('Location', validators=[Length(0, 64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

class EditProfileAdminForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(),Length(0,64),Email()])
    username = StringField('Username',validators=[DataRequired(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters numbers dots or underscores')])
    confirmed = BooleanField('Confirmed')
    role = SelectField('Role',coerce=int)   #select 是对<select》 的封装，功能是实现下拉列表 ps.109
    name = StringField('Role name',validators=[Length(0,64)])
    location = StringField('Location',validators=[Length(0,64)])
    about_me = TextAreaField('About me')
    submit = SubmitField('Submit')

    def __init__(self,user,*args,**kwargs):
        super(EditProfileAdminForm,self).__init__(*args,**kwargs)
        self.role.choices = [(role.id,role.name) for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):
        if field.data != self.user.email and \
                User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if field.data != self.user.username and \
                User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

class PostForm(FlaskForm):
    body = PageDownField("你的想法：",validators=[DataRequired()])
    submit = SubmitField('submit')

