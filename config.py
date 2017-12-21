import os
basedir = os.path.abspath(os.path.dirname(__file__))



class DevelopmentConfig(): 
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string' 
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True 
    FLASKY_MAIL_SUBJECT_PREFIX = 'Flasky' 
    FLASKY_MAIL_SUBJECT_PREFIX = 'Flasky'
    FLASKY_MAIL_SENDER = 'Flasky Admin <62607921@163.com>' 
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN') 
    FLASKY_POSTS_PER_PAGE= 5
 
    DEBUG = True 
    MAIL_SERVER = 'smtp.163.com' 
    MAIL_PORT = 25
    MAIL_USE_TLS = True 
    MAIL_USERNAME =  '62607921@163.com'
    MAIL_PASSWORD =  'fengshi1990'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite') 
    SQLALCHEMY_TRACK_MODIFICATIONS = True
 
class TestingConfig(): 
    TESTING = True 
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'data-test.sqlite') 
 
class ProductionConfig(): 
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'data.sqlite') 
 