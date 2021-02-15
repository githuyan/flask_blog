# -*- coding: UTF-8 -*-
from random import randint
from sqlalchemy.exc import IntegrityError
from faker import Faker
from .import db
from .models import User,Post

def users(count=100):
    fake =Faker() # 骗子，伪造的，随机生成信息
    i = 0
    while i<count:
        u = User(email=fake.email(),
                 username=fake.user_name(),
                 password = 'password',
                 confirm = True,
                 name = fake.name(),
                 location = fake.city(),
                 about_me = fake.text(),
                 member_since = fake.past_date())
        db.session.add(u)
        try:
            db.session.commit()
            i += 1
        except IntegrityError:  # ps.120  当伪造信息重复添加时，会爆这个错误
            db.session.rollback()
def posts(count=100):
    fake = Faker()
    user_count = User.query.count()
    for i in range(count):
        u = User.query.offset(randint(0,user_count-1)).first()
        p = Post(body=fake.text(),
                 # timestamp=fake.past_date(),
                 author=u)
        db.session.add(p)
    db.session.commit()