from flask import Blueprint, render_template, request, flash, redirect, url_for, json, jsonify
from .models import User, User_role_change_request, Equipment, Image, Request
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from sqlalchemy import and_, or_, not_
from flask_login import login_user, login_required, logout_user, current_user
from .sendpassword import generate_password
from .sendpassword import send_password
from flask_paginate import Pagination, get_page_parameter, get_page_args
from werkzeug.utils import secure_filename
import os
import requests
from datetime import datetime

auth = Blueprint('auth', __name__)


ACCESS = {
    'Guest': 0,
    'Research Assistant': 1,
    'Project PI':2,
    'Lab Manager':3,
    'Admin': 4
}

ROLE = {
    0: 'Guest',
    1: 'Research Assistant',
    2: 'Project PI',
    3: 'Lab Manager',
    4: 'Admin'
}

STATUS = {
    1: 'Available',
    2: 'Archived',
    3: 'Borrowed'
}


REQUEST_STATUS = {
    1: 'Pending',
    2: 'Approved',
    3: 'Rejected',
    4: 'Active',
    5: 'Finished'
}

@auth.context_processor
def base():
    number_of_user_role_change_request = User_role_change_request.query.count()
    return dict(ROLE=ROLE, 
                number_of_user_role_change_request = number_of_user_role_change_request,
                STATUS=STATUS,
                REQUEST_STATUS=REQUEST_STATUS
                )
    
@auth.route('/')
def home():    
    
    equipments = Equipment.query.filter(or_(Equipment.owner != 'Thanh',
                                            Equipment.location == 'JB305')).all() 
    nequips = len(equipments)
    # equipments = Equipment.query.filter(Equipment.owner.like('%{pattern}%'.format(pattern='h')) ).all() 
    return render_template("home.html", nequips =nequips , 
                                        list_of_equipments = list_of_equipments,
                                        equipments = equipments
                                        )

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        user_name = email[:email.index('@')]
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        # elif ('@vinuni.edu.vn' not in email):
        #     flash('Email must be a vinuni email', category='error')
        elif (len(first_name) < 2):
            flash('First name must be at least 2 characters!', category='error')
        elif (len(last_name) < 2):
            flash('Last name must be at least 2 characters!', category='error')
        else:
            user_password =  generate_password()
            new_user = User(email, first_name, last_name, user_name, 0, 
                            generate_password_hash(user_password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            mes = """We've emailed you a password. You should be receiving them shortly. 
            If you don't receive an email, please make sure you've entered the address you registered with, and check your spam folder.
            See you soon!"""
            flash(mes, category='info')
            send_password(email, user_password, 'Welcome')
            return redirect(url_for('auth.login'))

    return render_template("sign_up.html")


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('auth.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html")


@auth.route('/passwordRecovery', methods=['GET', 'POST'])
def passwordRecovery():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Password recovery letter has been sent successfully', category='success')
            new_password =  generate_password()
            user.password = generate_password_hash(new_password, method='sha256')
            db.session.commit()
            send_password(email, new_password, 'Password recovery')
            return redirect(url_for('auth.login'))
        else:
            flash('Email does not exist.', category='error')
    return render_template('passwordRecovery.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(user_name=username).first_or_404() 
    return render_template('user_details.html', user=user)


@auth.route('/profile/<string:username>/edit-profile', methods=['GET', 'POST'])
@login_required
def editprofile(username):
    if current_user.user_name != username:
        return redirect(request.referrer)
    if (request.method == 'POST'):
        new_first_name = request.form.get('new_first_name')
        new_last_name = request.form.get('new_last_name')
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        new_role = int(request.form.get('new_category'))
      
        changes = []
        if (len(new_first_name) > 0):
           changes.append(('change first name', new_first_name))
        if (len(new_last_name) > 0):
            changes.append(('change last name', new_last_name))
        if (len(old_password) > 0 or len(new_password) > 0 or len(confirm_new_password) > 0):
            changes.append(('change password', old_password, new_password, confirm_new_password))
        if (current_user.access != new_role):
            changes.append(('change category', new_role))
            
        check_valid = True

        for change in changes:
            if (change[0] == 'change first name' and len(new_first_name) < 2):
                flash('First name must be at least 2 characters', category='error')
                check_valid = False
                break
            if (change[0] == 'change last name' and len(new_last_name) < 2):
                flash('Last name must be at least 2 characters', category='error')
                check_valid = False
                break
            if (change[0] == 'change password'):
                if (check_password_hash(current_user.password, old_password) == False):
                    flash('Invalid current password', category='error')
                    check_valid = False
                    break
                if (len(new_password) < 6):
                    flash('New password must be  at least 6 characters')
                    check_valid = False
                    break
                if (new_password != confirm_new_password):
                    flash('Password and confirm password does not match', category='error')
                    check_valid = False
                    break
            if (change[0] == 'change category'):
                change_request = User_role_change_request.query.filter_by(new_role = new_role, user_id = current_user.id).first()
                if (change_request):
                    flash('You\'ve already requested this', category='error')
                    check_valid = False
                    break
            
        if (check_valid == False):
            return redirect(url_for('auth.editprofile', username=username))
        info_changed = False
        for change in changes:
            if (change[0] == 'change first name'):
                current_user.first_name = new_first_name
                info_changed = True
            if (change[0] == 'change last name'):
                current_user.last_name = new_last_name
                info_changed = True
            if (change[0] == 'change password'):
                current_user.password = generate_password_hash(new_password, method='sha256')
                info_changed = True
            if (change[0] == 'change category'):
                flash('Please wait for the admin to accpet your request', category='info')
                new_request = User_role_change_request(current_user.id, current_user.user_name, new_role)
                db.session.add(new_request)
        if (info_changed == True): 
            flash('Changes have been updated', category='success')
        db.session.commit()
        return redirect(url_for('auth.editprofile', username=username))
    return render_template('edit_profile.html', user=current_user)

@auth.route('/profile/<string:username>/personal-requests', methods=['GET', 'POST'])
def personal_requests(username):
    user = User.query.filter_by(user_name = username).first_or_404()
    
    
    request_list = Request.query.filter(Request.user_name == user.user_name)
    request_list = list(request_list)
    total = len(request_list)

    def condition(request):
        return request.date_requested
    request_list.sort(key = condition)
    
    request_list.reverse()
    
    def get_request(offset=0, per_page=10):
        return request_list[offset:offset+per_page]
    
        
    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    
    pagination_requests = get_request(offset=offset, per_page=per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')

    return render_template('personal_requests.html', 
                            user=user,
                            request_list=pagination_requests, total=total,  
                            page=page, per_page=per_page, pagination=pagination)


@auth.route('/admin/borrowing-request-list', methods=['GET', 'POST'])
@login_required
def borrowing_request_list():
    request_list = Request.query.order_by(Request.date_requested)
    request_list = list(request_list)
    request_list.reverse()
    total = len(request_list)

    def get_request(offset=0, per_page=10):
        return request_list[offset:offset+per_page]
    
        
    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    
    pagination_requests = get_request(offset=offset, per_page=per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('borrowing_request.html', 
                            request_list=pagination_requests, total=total,  
                            page=page, per_page=per_page, pagination=pagination)

@auth.route('/admin/user-role-change-request-list', methods=['GET', 'POST'])
@login_required
def user_role_change_request_list():
    if (current_user.access < 3):
        return "Page not found", 404
    user_role_change_request_list = User_role_change_request.query.order_by(User_role_change_request.date_added.desc())
    users = User.query.order_by(User.date_added)
    user_list = {}
    for user in users:
        user_list[user.user_name] = user
    return render_template('user_role_change_request_list.html', user_list = user_list, user_role_change_request_list = user_role_change_request_list)

@auth.route('/admin/request-list/user-role-change-request-list/reject/<int:id>', methods=['POST'])
@login_required
def reject_user_role_change_request(id):
    if (current_user.access < 3):
        return redirect(request.referrer)
    if request.method == 'POST':
        userChoice = request.form.get('userChoice2')
        if (userChoice == 'False'):
            return redirect(url_for('auth.user_role_change_request_list'))
        user_request = User_role_change_request.query.get_or_404(id)
        try:
            db.session.delete(user_request)
            db.session.commit()
            flash('Request was rejected!', category='info')
            return redirect(url_for('auth.user_role_change_request_list'))
        except:
            flash('Whoops! There was a problem doing this action, try again', category='error')
            return redirect(url_for('auth.user_role_change_request_list'))
        
@auth.route('/admin/request-list/user-role-change-request-list/accept/<int:id>', methods=['POST'])
@login_required
def accept_user_role_change_request(id):
    if (current_user.access < 3):
        return redirect(request.referrer)
    if request.method == 'POST':
        userChocie = request.form.get('userChoice')
        if (userChocie == 'False'):
            return redirect(url_for('auth.user_role_change_request_list'))
        user_request = User_role_change_request.query.get_or_404(id)
        try:
            user = User.query.filter_by(user_name = user_request.user_name).first()
            user.access = user_request.new_category
            db.session.delete(user_request)
            db.session.commit()
            flash('Request was accepted!', category='info')
            return redirect(url_for('auth.user_role_change_request_list'))
        except:
            flash('Whoops! There was a problem doing this action, try again', category='error')
            return redirect(url_for('auth.user_role_change_request_list'))

@auth.route('/users', methods=['GET', 'POST'])
def user_list():
    users = list(User.query.order_by(User.id))
    def get_users(offset=0, per_page=10):
        return users[offset:offset+per_page]
    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    total = len(users)
    pagination_users = get_users(offset=offset, per_page=per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    list_of_username = []
    for user in users:
        list_of_username.append(user.user_name)
    return render_template('user_list.html', list_of_username=list_of_username, users=pagination_users, page=page, per_page=per_page, pagination=pagination)

@auth.route('/users/search/<string:pattern>', methods=['GET', 'POST'])
def user_list_show_result(pattern):
    users = []
    list_of_users = User.query.filter(User.user_name == pattern).all()
    users = list(list_of_users)
    def get_users(offset=0, per_page=10):
        return users[offset:offset+per_page]
    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    total = len(users)
    pagination_users = get_users(offset=offset, per_page=per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    list_of_username = []
    for user in users:
        list_of_username.append(user.user_name)
    return render_template('user_list_show_result.html', pattern=pattern, list_of_username=list_of_username, users=pagination_users, page=page, per_page=per_page, pagination=pagination)

@auth.route('/admin/edit-profile/<string:username>', methods=['GET', 'POST'])
@login_required
def admin_edit_user_profile(username):
    if (current_user.access < 3):
        return "Page not found", 404
    user = User.query.filter_by(user_name = username).first()
    if request.method == 'POST':
        new_first_name = request.form.get('new_first_name')
        new_last_name = request.form.get('new_last_name')
        new_category = int(request.form.get('new_category'))
        changes = []
        if (len(new_first_name) > 0):
           changes.append(('change first name', new_first_name))
        if (len(new_last_name) > 0):
            changes.append(('change last name', new_last_name))
        if (current_user.access != new_category):
            changes.append(('change category', new_category))
            
        check_valid = True
        
        for change in changes:
            if (change[0] == 'change first name' and len(new_first_name) < 2):
                flash('First name must be at least 2 characters', category='error')
                check_valid = False
                break
            if (change[0] == 'change last name' and len(new_last_name) < 2):
                flash('Last name must be at least 2 characters', category='error')
                check_valid = False
                break
        if (check_valid == False):
            return redirect(url_for('auth.admin_edit_user_profile', username=username))
        info_changed = False
        for change in changes:
            if (change[0] == 'change first name'):
                user.first_name = new_first_name
                info_changed = True
            if (change[0] == 'change last name'):
                user.last_name = new_last_name
                info_changed = True
            if (change[0] == 'change category'):
                user.access = new_category
                info_changed = True
        if (info_changed == True):
            flash('Changes have been updated', category='success')
        db.session.commit()
        return redirect(url_for('auth.admin_edit_user_profile', username=username))
    return render_template('admin_edit_user_profile.html', user=user)


@auth.route('/admin/delete-user/<int:id>', methods=['POST'])
@login_required
def admin_delete_user(id):
    if (current_user.access < 3):
            return redirect(request.referrer)
    if request.method == 'POST':
        userChoice = request.form.get("userChoice")
        if (userChoice == 'False'):
            return redirect(request.referrer)
        user = User.query.get_or_404(id)
        try:
            db.session.delete(user)
            db.session.commit()
            flash('{fname} was deleted'.format(fname=user.user_name), category='info')
            return redirect(request.referrer)
        except:
            flash('Whoops! There was a problem doing this action, try again', category='error')
            return redirect(request.referrer)

@auth.route('/equipments', methods=['GET', 'POST'])
def list_of_equipments(): 
    equipments = list(Equipment.query.order_by(Equipment.status))
    list_of_owners = set()
    list_of_locations = set()
    list_of_types = set()
    
    for equip in equipments:
        list_of_owners.add(equip.owner)
        list_of_locations.add(equip.location)
        list_of_types.add(equip.type)
    
    list_of_owners = list(list_of_owners)
    list_of_locations = list(list_of_locations)
    list_of_types = list(list_of_types)
    search_by_name = request.args.get('search')
    search_by_type = request.args.get('type') 
    search_by_owner = request.args.get('owner')
    search_by_working_condition = request.args.get('working_condition') 
    search_by_status = request.args.get('status') 
    if not search_by_type:
        search_by_type = 'All'
    search_by_location = request.args.get('location')
    if not search_by_location:  
        search_by_location = 'All'
    if not search_by_owner:
        search_by_owner = 'All'
    if search_by_name:
        tmp = []
        for equip in equipments:
            if search_by_name.lower() in equip.name.lower():
                tmp.append(equip)
        equipments = tmp 
    if search_by_type != 'All':
        tmp = []
        for equip in equipments:
            if equip.type == search_by_type:
                tmp.append(equip)
        equipments = tmp
    if search_by_location != 'All':
        tmp = []
        for equip in equipments:
            if equip.location == search_by_location:
                tmp.append(equip)        
        equipments = tmp
    if search_by_owner != 'All':
        tmp = []
        for equip in equipments:
            if equip.owner == search_by_owner:
                tmp.append(equip)
        equipments = tmp
   
    if search_by_working_condition:
        tmp = []
        for equip in equipments:
            if equip.working_condition == search_by_working_condition:
                tmp.append(equip)
        equipments = tmp
        
    if search_by_status:
        tmp = []
        for equip in equipments:
            if equip.status == int(search_by_status):
                tmp.append(equip)
        equipments = tmp
    def get_equipment(offset=0, per_page=10):
        return equipments[offset:offset+per_page]
    page, per_page, offset = get_page_args(page_parameter="page", per_page_parameter="per_page")
    total = len(equipments)
    pagination_users = get_equipment(offset=offset, per_page=per_page)
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    list_of_images = list(Image.query.order_by(Image.equip_id))
    images = {}
    pre = -1
    cur_list = []
    for image in list_of_images:
        if image.equip_id != pre:
            images[pre] = cur_list
            cur_list = []
        pre = image.equip_id
        cur_list.append(image.filepath)
    images[pre] = cur_list

    
    
    return render_template('list_of_equipments.html',  
                            list_of_owners=list_of_owners,
                            list_of_types=list_of_types,
                            list_of_locations=list_of_locations,
                            equipments=pagination_users, 
                            page=page, 
                            per_page=per_page, 
                            pagination=pagination,
                            images = images,
                            search_by_name = search_by_name,
                            search_by_type = search_by_type,
                            search_by_location = search_by_location,
                            search_by_owner = search_by_owner,
                            total = total)
    
    
    
@auth.route('/equipments/overall', methods=['GET', 'POST'])
def equipments_overall():
    equipments = list(Equipment.query.order_by(Equipment.status))
    list_of_types = set()
    
    for equip in equipments:
        list_of_types.add(equip.type)
    rows = []
    for type in list_of_types:
        new_row = []
        new_row.append(type)
        total = Equipment.query.filter(Equipment.type == type).count()  
        good_working_condition = Equipment.query.filter(and_(Equipment.working_condition == 'Yes',
                                                             Equipment.type == type)).count()
        poor_working_condition = total - good_working_condition     
        being_borrowed = Equipment.query.filter(and_(Equipment.status == 3,
                                                     Equipment.type == type)).count()
        new_row.append(good_working_condition)
        new_row.append(poor_working_condition)
        new_row.append(being_borrowed)
        new_row.append(total)
        rows.append(new_row)
    return render_template('equipments_overall.html', rows = rows)

@auth.route('/equipments/details/<string:equip_name>', methods=['GET', 'POST'])
def equipment_details(equip_name):
    equip = Equipment.query.filter_by(name=equip_name).first_or_404()
    list_of_images = list(Image.query.filter_by(equip_id=equip.id))
    images = []
    for image in list_of_images:
        images.append(image)
    len_image = len(list_of_images)
    
   
    return render_template('equipment_details.html', equip=equip, images = images, len_image = len_image)

@auth.route('/equipments/details/<string:equip_name>/edit', methods=['GET', 'POST'])
@login_required
def edit_equipment_details(equip_name):
    if request.method == 'POST':
        equip = Equipment.query.filter_by(name=equip_name).first_or_404()
        new_name = request.form.get('equip-name')
        new_type = request.form.get('equip-type')
        new_owner = request.form.get('equip-owner')
        new_location = request.form.get('equip-location')
        new_status = int(request.form.get('equip-status'))
        new_working_condition = request.form.get('equip-working_condition')
        new_description = request.form.get('equip-description')
        new_comments = request.form.get('equip-comments')
        if (new_name != equip.name):
            tmp = Equipment.query.filter_by(name=new_name).first()
            if (tmp):
                flash('Please enter an other name', category='error')
                return redirect(request.referrer)
        equip.name = new_name
        equip.type = new_type
        equip.owner = new_owner
        equip.location = new_location
        equip.status = new_status
        equip.working_condition = new_working_condition
        equip.description = new_description
        equip.comments = new_comments
        db.session.commit()
        return redirect(request.referrer)    
       
    return redirect(request.referrer)
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@auth.route('/equipments/new_equipment', methods=['POST'])
def new_equipment():
    if request.method == 'POST':
        equip_name =  request.form.get('equip-name')
        words = equip_name.split()
        equip_name = '-'.join(words)
        equip = Equipment.query.filter_by(name=equip_name).first()
        if (equip):
            flash('Please enter another name', category='error')
            return redirect(url_for('auth.list_of_equipments'))
        equip_type = request.form.get('equip-type')
        equip_owner =  request.form.get('equip-owner')
        equip_location =  request.form.get('equip-location')
        equip_status = int(request.form.get('equip-status'))
        equip_description = request.form.get('equip-description')   
        equip_working_condition = request.form.get('equip-working_condition')
        equip_comments = request.form.get('equip-comments')
        new_equip = Equipment(equip_name, equip_type, equip_owner, equip_location, 
                          equip_status, equip_description, equip_working_condition,
                          equip_comments)
        files = request.files.getlist('files[]')
        if len(files) > 4:
            flash('Number of files must be less than 5', category='error')
            return redirect(url_for('auth.list_of_equipments'))
        valid = True
        for file in files:
            if file and allowed_file(file.filename):
                pass
            else:
                if (len(file.filename) == 0):
                    continue
                valid = False
                break
        if valid == False:
            flash('Invalid file', category='error')
            return  redirect(url_for('auth.list_of_equipments'))
        db.session.add(new_equip)
        db.session.commit()
        equip = Equipment.query.filter_by(name=equip_name).first()
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join('D:\code\project\web\images', filename))
                new_image = Image(equip.id, filename)
                db.session.add(new_image)
                db.session.commit()
        
        return redirect(url_for('auth.list_of_equipments'))
    
@auth.route('/equipments/delete-equipment/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_equipment(id):
    if (current_user.access < 3):
        return redirect(request.referrer)
    if request.method == 'POST':
        userChoice = request.form.get('userChoice')
        equip = Equipment.query.filter_by(id = id).first_or_404()
        if (userChoice == 'False'):
            return redirect(request.referrer)         
        
        equip_imgs = Image.query.filter_by(equip_id=equip.id)
        for equip_img in equip_imgs:
            img = Image.query.filter_by(id = equip_img.id).first_or_404()
            try:
                db.session.delete(img)
                db.session.commit()
            except:
                flash('Whoops! There was a problem doing this action, try again', category='error')
                return redirect(request.referrer)
        try:
            db.session.delete(equip)
            db.session.commit()
        except:
            flash('Whoops! There was a problem doing this action, try again', category='error')
            return redirect(request.referrer)
        flash('Equipment was deleted!', category='success')
        return redirect(url_for('auth.list_of_equipments'))
    return redirect(request.referrer)

@auth.route('/equipments/details/<string:equip_name>delete-image/<int:id>', methods=['POST'])
@login_required
def delete_image(equip_name, id):
    if (current_user.access < 3):
        return redirect(request.referrer)
    
    if request.method == 'POST':
        userChoice = request.form.get('userChoice_del_img') 
        if userChoice == 'False':
            return redirect(url_for('auth.equipment_details', equip_name=equip_name))
        
        img = Image.query.filter_by(id=id).first_or_404()
        try:
            db.session.delete(img)
            db.session.commit()
        except:
            flash('Whoops! There was a problem doing this action, try again', category='error')
            return redirect('auth.equipment_details', equip_name=equip_name)
        flash('Image was delted')
        return redirect(url_for('auth.equipment_details', equip_name=equip_name))
    return redirect(request.referrer)
        
@auth.route('/equipments/details/<string:equip_name>/add-image', methods=['POST'])
@login_required
def add_image(equip_name):
    if (current_user.access < 3):
        return redirect(request.referrer)
    if request.method == 'POST':
        files = request.files.getlist('imagefile[]')
     
        valid = True
        for file in files:
            if file and allowed_file(file.filename):
                pass
            else:
                if (len(file.filename) == 0):
                    
                    valid = False
                    break

        if valid == False:
            flash('Invalid file', category='error')
            return  redirect(url_for('auth.equipment_details', equip_name = equip_name))
        equip = Equipment.query.filter_by(name=equip_name).first()
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join('D:\code\project\web\images', filename))
                new_image = Image(equip.id, filename)
                db.session.add(new_image)
                db.session.commit()
        flash("An image has been added", category='success')
        return redirect(url_for('auth.equipment_details', equip_name=equip_name))
    return redirect(request.referrer)

 
 
@auth.route('/send-request/user-<string:user_name>/equipment-<string:equip_name>', methods=['POST', 'GET'])
@login_required
def send_request(user_name, equip_name):
    if request.method == 'POST':
        user = User.query.filter_by(user_name = user_name).first_or_404()
        equip = Equipment.query.filter_by(name = equip_name).first_or_404()
        term_of_use = request.form.get("term_of_use")
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        comments = request.form.get("comments")
        new_request = Request(user_name = user_name, 
                              equip_name = equip_name,
                              term_of_use = term_of_use, 
                              start_date = start_date, 
                              end_date = end_date,
                              comments = comments, 
                              status = 1) 
        db.session.add(new_request)
        db.session.commit()
        return redirect(request.referrer)
    
@auth.route('/admin/borrowing-request-list/accept-request/<int:id>', methods=['GET', 'POST'])
@login_required
def accept_borrowing_request(id):
    if current_user.access < 3: 
        return redirect(request.referrer)
    
    if request.method == 'POST':
        request_ = Request.query.filter_by(id = id).first_or_404()
        userChoice = request.form.get("userChoice")
        
        if userChoice == 'False':
            return redirect(request.referrer)
       
        equip = Equipment.query.filter_by(name = request_.equip_name).first_or_404()
        if equip.status != 1:
            flash('Cannot approve this request', category='error')
            return redirect(request.referrer)
        request_.status = 2
        equip.status = 3
        db.session.commit()
        flash('Request has been approved', category='success')
        return redirect(request.referrer)

    return redirect(request.referrer)
    
@auth.route('/admin/borrowing-request-list/reject-request/<int:id>', methods=['GET', 'POST'])
@login_required
def reject_borrowing_request(id):
    if current_user.access < 3: 
        return redirect(request.referrer)
    
    if request.method == 'POST':
        userChoice = request.form.get("userChoice2")
        if userChoice == 'False':
            return redirect(request.referrer)

        request_ = Request.query.filter_by(id = id).first_or_404()
        request_.status = 3
        equip = Equipment.query.filter_by(name = request_.equip_name).first_or_404()
        equip.status = 1
        db.session.commit()
        flash('Request hast been rejected', category='success')
        return redirect(request.referrer)

    return redirect(request.referrer)
    