from flask import Blueprint, render_template
from flask_login import login_required, current_user
from .models import User, User_role_change_request, Equipment, Image
import os


views = Blueprint('views', __name__)

