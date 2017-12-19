from datetime import datetime 
from flask import render_template, session, redirect, url_for,g
from flask_login import current_user
 
from . import main 
from .forms import NameForm 
from .. import db 
from ..models import User 
 
@main.route('/', methods=['GET', 'POST']) 
def index(): 

    return render_template('index.html') 
