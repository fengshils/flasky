from flask import Flask, render_template 
from flask_bootstrap import Bootstrap 
from flask_mail import Mail 
from flask_moment import Moment 
from flask_sqlalchemy import SQLAlchemy 
from config import DevelopmentConfig 
from flask_login import LoginManager


bootstrap = Bootstrap() 
mail = Mail() 
moment = Moment() 
db = SQLAlchemy()
login_manager = LoginManager() 
login_manager.session_protection = 'strong' 
login_manager.login_view = 'auth.login' 
 
def create_app(config_name): 
    app = Flask(__name__) 
    app.config.from_object(DevelopmentConfig) 
 
    bootstrap.init_app(app) 
    mail.init_app(app) 
    moment.init_app(app) 
    db.init_app(app)
    login_manager.init_app(app) 
 
    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    from app.auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    # 附加路由和自定义的错误页面 
 
    return app