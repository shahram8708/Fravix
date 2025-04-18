from flask import Flask, render_template, redirect, url_for, request, flash, session, send_from_directory, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import random
from datetime import datetime
import secrets 
import re
import os
import bcrypt
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from flask_mail import Mail, Message
from flask_session import Session
from datetime import timedelta

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://fravix_user:2DuiVbGuTTopCYiNkbCNSioZqaokX974@dpg-d00rs6qdbo4c73dkbjs0-a.singapore-postgres.render.com/fravix'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = True 
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365) 

Session(app)
app.config['SECRET_KEY'] = secrets.token_hex(16) 
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'elibraryvgec@gmail.com'  
app.config['MAIL_PASSWORD'] = 'affj ajfj kvyc mzdo'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'elibraryvgec@gmail.com'  

mail = Mail(app)

@app.route('/our_team')
def our_team():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = []  
        
    return render_template('our_team.html', unread_count=unread_count, notifications=notifications)

@app.route('/contact', methods=['GET'])
def contact():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 

    return render_template('contact.html', unread_count=unread_count, notifications=notifications)

@app.route('/terms_conditions')
def terms_conditions():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = []  

    return render_template('terms_conditions.html', unread_count=unread_count, notifications=notifications)

@app.route('/privacy_policy')
def privacy_policy():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:                   
        unread_count = 0
        notifications = []  
    
    return render_template('privacy_policy.html', unread_count=unread_count, notifications=notifications)

@app.route('/chatbot')
@login_required
def chatbot():
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('chatbot.html', unread_count=unread_count, notifications=notifications)

@app.route('/send_message', methods=['POST'])
def send_message():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    message = request.form['message']

    msg = Message(
        subject='Fravix E-Library Contact Form Submission',
        sender='elibraryvgec@gmail.com',
        recipients=['elibraryvgec@gmail.com']
    )
    msg.body = f"Name: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"

    try:
        mail.send(msg)
        flash('Your message has been sent!', 'success')
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'danger')
    
    return redirect(url_for('contact'))

@app.route('/download/<path:filename>', methods=['GET'])
@login_required
def download_file(filename):
    upload_directory = os.path.join(app.root_path, 'uploads')  

    try:
        return send_from_directory(upload_directory, filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)

@app.route('/delete_resource/<int:resource_id>', methods=['POST'])
@login_required 
def delete_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)

    if resource.user_id != current_user.id: 
        abort(403) 

    for rating in resource.ratings:
        db.session.delete(rating)

    for fav in Favourite.query.filter_by(resource_id=resource.id).all():
        db.session.delete(fav)

    db.session.delete(resource)
    db.session.commit()

    flash('Resource deleted successfully.', 'success')

    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return redirect(url_for('home', unread_count=unread_count, notifications=notifications)) 

user_followers = db.Table('user_followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_number = db.Column(db.String(100), nullable=False)
    subscription_type = db.Column(db.String(50), nullable=False)
    subscription_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_date = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref='subscriptions', lazy=True)

@app.route('/process_payment', methods=['POST'])
@login_required
def process_payment():
    subscription_type = request.form['subscription_type']
    transaction_number = request.form['transaction_number']

    expiry_date = calculate_expiry(subscription_type)

    subscription = Subscription(
        user_id=current_user.id,
        transaction_number=transaction_number,
        subscription_type=subscription_type,
        subscription_date=datetime.utcnow(),
        expiry_date=expiry_date
    )
    db.session.add(subscription)
    db.session.commit()

    admin_email = 'elibraryvgec@gmail.com' 
    msg = Message('New Subscription Alert',
                  recipients=[admin_email])
    msg.body = f"""
A new subscription has been created:

User Details:
- User ID: {current_user.id}
- Name: {current_user.username}
- Email: {current_user.email}

Subscription Details:
- Subscription Type: {subscription_type}
- Transaction Number: {transaction_number}
- Expiry Date: {expiry_date if expiry_date else 'Lifetime'}

Best regards,
The Fravix E-Library Team 📚
    """
    mail.send(msg)

    current_user.subscription_status = "Pending Confirmation"
    current_user.subscription_type = subscription_type
    current_user.subscription_expiry = expiry_date if expiry_date else None
    db.session.commit()

    return redirect(url_for('subscription_status'))

from datetime import datetime, timedelta

def calculate_expiry(subscription_type):
    if subscription_type == '1 Month':
        return datetime.utcnow() + timedelta(days=30)
    elif subscription_type == '3 Months':
        return datetime.utcnow() + timedelta(days=90)
    elif subscription_type == '6 Months':
        return datetime.utcnow() + timedelta(days=180)
    elif subscription_type == '1 Year':
        return datetime.utcnow() + timedelta(days=365)
    elif subscription_type == 'Lifetime':
        return datetime.utcnow() + timedelta(days=365 * 100)
    return None 

@app.route('/subscribe', methods=['GET', 'POST'])
@login_required
def subscribe():
    if current_user.subscription_status in ['Active', 'Pending Confirmation', 'Expired']:
        return redirect(url_for('subscription_status'))
    
    if request.method == 'POST':
        subscription_type = request.form.get('subscription_type')
        transaction_number = request.form.get('transaction_number')

        if subscription_type == '1 Month':
            expiry_date = datetime.utcnow() + timedelta(days=30)
        elif subscription_type == '3 Months':
            expiry_date = datetime.utcnow() + timedelta(days=90)
        elif subscription_type == '6 Months':
            expiry_date = datetime.utcnow() + timedelta(days=180)
        elif subscription_type == '1 Year':
            expiry_date = datetime.utcnow() + timedelta(days=365)
        elif subscription_type == 'Lifetime':
            expiry_date = None 

        subscription = Subscription(
            user_id=current_user.id,
            transaction_number=transaction_number,
            subscription_type=subscription_type,
            expiry_date=expiry_date
        )
        db.session.add(subscription)
        db.session.commit()

        current_user.subscription_status = "Pending Confirmation"
        current_user.subscription_type = subscription_type
        db.session.commit()

        return redirect(url_for('subscription_status'))  
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return render_template('subscription.html', unread_count=unread_count, notifications=notifications) 

@app.route('/admin/subscriptions')
def admin_subscriptions():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    subscriptions = Subscription.query.join(User).filter(User.subscription_status.in_(['Pending Confirmation', 'Active'])).all()

    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()

    return render_template('admin_dashboard.html', 
                           subscriptions=subscriptions, 
                           unread_count=unread_count, 
                           notifications=notifications)

@app.route('/admin/approve_subscription/<int:subscription_id>', methods=['POST'])
def approve_subscription(subscription_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    
    subscription = Subscription.query.get(subscription_id)
    user = subscription.user

    subscription.status = 'Approved'
    user.subscription_status = 'Active'
    user.subscription_expiry = subscription.expiry_date
    db.session.commit()

    msg = Message('Your Subscription is Approved',
                  recipients=[user.email])
    msg.body = f"""
Congratulations, your subscription has been approved!

Subscription Details:
- Subscription Type: {subscription.subscription_type}
- Transaction Number: {subscription.transaction_number}
- Expiry Date: {subscription.expiry_date if subscription.expiry_date else 'Lifetime'}

Thank you for subscribing!

Best regards,
The Fravix E-Library Team 📚
    """
    mail.send(msg)

    return redirect(url_for('admin_dashboard'))

@app.route('/subscription/status')
@login_required
def subscription_status():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return render_template('subscription_status.html', user=current_user, unread_count=unread_count, notifications=notifications)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    active_session = db.Column(db.String(150), nullable=True)
    favourites = db.relationship('Favourite', backref='user', lazy=True)
    is_verified = db.Column(db.Boolean, default=False)
    branch = db.Column(db.String(50), nullable=True)
    college = db.Column(db.String(150), nullable=False, default="")
    bio = db.Column(db.Text, nullable=True)
    points = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    groups = db.relationship('GroupMembership', backref='user', lazy=True)
    group_messages = db.relationship('GroupMessage', backref='user', lazy=True)
    products = db.relationship('Product', backref='user', lazy=True)
    subscription_status = db.Column(db.String(50), nullable=True)
    subscription_type = db.Column(db.String(50), nullable=True)
    subscription_expiry = db.Column(db.DateTime, nullable=True)
    def get_enrollment_number(self):
        return self.email 
    
    followed = db.relationship(
        'User', secondary=user_followers,
        primaryjoin=(user_followers.c.follower_id == id),
        secondaryjoin=(user_followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(user_followers.c.followed_id == user.id).count() > 0
    
    def follower_count(self):
        return self.followers.count()

    def followed_count(self):
        return self.followed.count()

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    icon = db.Column(db.String(150), nullable=True)
    is_public = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    members = db.relationship('GroupMembership', backref='group', lazy=True)
    group_messages = db.relationship('GroupMessage', backref='group', lazy=True)

class GroupMembership(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

class GroupMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/promote_to_admin/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
def promote_to_admin(group_id, user_id):
    group = Group.query.get_or_404(group_id)

    if group.created_by != current_user.id:
        flash("Only the group admin can promote members.", "danger")
        return redirect(url_for('group_list'))

    membership = GroupMembership.query.filter_by(group_id=group_id, user_id=user_id).first()
    
    if membership and not membership.is_admin:
        membership.is_admin = True
        db.session.commit()

        admin_notification = Notification(
            user_id=membership.user.id,
            sender_id=current_user.id,
            notification_type='admin_promotion',
            msg=f'You have been promoted to admin in the group {group.name}.',
            is_read=False
        )
        db.session.add(admin_notification)

        group_list_url = url_for('group_list', _external=True)
        msg = Message(
            subject="Admin Promotion Notification",
            recipients=[membership.user.email],
            body=f"Dear {membership.user.username},\n\n"
                 f"You have been promoted to admin in the group '{group.name}'.\n\n"
                 f"Click here to view your groups: {group_list_url}\n\n"
                 "Best regards,\nThe Fravix E-Library Team 📚"
        )
        mail.send(msg)

        db.session.commit()

        flash(f'{membership.user.username} has been promoted to admin.', 'success')
    else:
        flash('User is already an admin or not found in the group.', 'danger')
    
    return redirect(url_for('group_chat', group_id=group.id))

@app.route('/demote_from_admin/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
def demote_from_admin(group_id, user_id):
    group = Group.query.get_or_404(group_id)

    if group.created_by != current_user.id:
        flash("Only the group admin can demote members.", "danger")
        return redirect(url_for('group_list'))

    membership = GroupMembership.query.filter_by(group_id=group_id, user_id=user_id).first()
    
    if membership and membership.is_admin:
        membership.is_admin = False
        db.session.commit()

        admin_notification = Notification(
            user_id=membership.user.id,
            sender_id=current_user.id,
            notification_type='admin_demotion',
            msg=f'You have been demoted from admin in the group {group.name}.',
            is_read=False
        )
        db.session.add(admin_notification)

        group_list_url = url_for('group_list', _external=True)
        msg = Message(
            subject="Admin Demotion Notification",
            recipients=[membership.user.email],
            body=f"Dear {membership.user.username},\n\n"
                 f"You have been demoted from admin in the group '{group.name}'.\n\n"
                 f"Click here to view your groups: {group_list_url}\n\n"
                 "Best regards,\nThe Fravix E-Library Team 📚"
        )
        mail.send(msg)

        db.session.commit()

        flash(f'{membership.user.username} has been demoted from admin.', 'success')
    else:
        flash('User is not an admin or not found in the group.', 'danger')
    
    return redirect(url_for('group_chat', group_id=group.id))

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        is_public = request.form.get('is_public') == 'public'
        
        new_group = Group(name=name, description=description, is_public=is_public, created_by=current_user.id)
        db.session.add(new_group)
        db.session.commit()
        flash('Group created successfully', 'success')
        return redirect(url_for('group_list'))
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return render_template('create_group.html', unread_count=unread_count, notifications=notifications)

@app.route('/groups')
@login_required
def group_list():
    groups = Group.query.all()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    users = User.query.all() 
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return render_template('group_list.html', groups=groups, users=users, unread_count=unread_count, notifications=notifications)

class DeletedMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('group_message.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/delete_chats/<int:group_id>', methods=['POST'])
@login_required
def delete_chats(group_id):

    group = Group.query.get_or_404(group_id)

    membership = GroupMembership.query.filter_by(group_id=group.id, user_id=current_user.id).first()

    if not membership or not membership.is_admin:

        if group.created_by != current_user.id:
            flash("Only the group admin can delete messages.", "danger")
            return redirect(url_for('group_list'))

    messages = GroupMessage.query.filter_by(group_id=group_id).all()

    if not messages:
        flash("No chat messages found for this group.", "info")
        return redirect(url_for('group_list'))

    deleted_count = 0

    for message in messages:

        db.session.delete(message)

        deleted_message = DeletedMessage(user_id=current_user.id, message_id=message.id)
        db.session.add(deleted_message)
        
        deleted_count += 1

    db.session.commit()

    if deleted_count > 0:
        flash(f"{deleted_count} chat message(s) have been deleted on this device.", "success")
    else:
        flash("No chat messages to delete.", "info")

    return redirect(url_for('group_list'))

@app.route('/delete_group/<int:group_id>', methods=['POST'])
@login_required
def delete_group(group_id):
    group = Group.query.get_or_404(group_id)

    if group.created_by != current_user.id:
        flash("Only the group admin can delete the group.", "danger")
        return redirect(url_for('group_list'))

    GroupMembership.query.filter_by(group_id=group_id).delete()

    GroupMessage.query.filter_by(group_id=group_id).delete()

    db.session.delete(group)
    db.session.commit()
    
    flash("Group and all its messages and members have been deleted.", "success")
    return redirect(url_for('group_list'))

@app.route('/edit_group/<int:group_id>', methods=['GET', 'POST'])
@login_required
def edit_group(group_id):
    group = Group.query.get_or_404(group_id)
    if group.created_by != current_user.id:
        flash("Only the group admin can edit this group.", "danger")
        return redirect(url_for('group_list'))
    
    if request.method == 'POST':
        group.name = request.form.get('name')
        group.description = request.form.get('description')
        group.is_public = request.form.get('is_public') == 'on'
        db.session.commit()
        flash("Group details updated successfully.", "success")
        return redirect(url_for('group_list'))
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return render_template('edit_group.html', group=group, unread_count=unread_count, notifications=notifications)

@app.route('/join_group/<int:group_id>', methods=['POST'])
@login_required
def join_group(group_id):
    group = Group.query.get_or_404(group_id)

    existing_membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group.id).first()
    
    if not existing_membership:

        membership = GroupMembership(user_id=current_user.id, group_id=group.id, is_approved=group.is_public)
        db.session.add(membership)
        db.session.commit()

        group_list_url = url_for('group_list', _external=True)

        if group.is_public:

            admin_notification = Notification(
                user_id=group.created_by,
                sender_id=current_user.id,
                notification_type='join_request',
                msg=f'User {current_user.username} has joined your public group {group.name}.',
                is_read=False
            )
            db.session.add(admin_notification)
            db.session.commit()

            admin_email = User.query.get(group.created_by).email
            msg = Message(
                subject="User Joined Your Group",
                recipients=[admin_email],
                body=f"Dear Group Admin,\n\n"
                     f"User {current_user.username} has joined your public group '{group.name}'.\n\n"
                     f"View all your groups here: {group_list_url}\n\n"
                     "Best regards,\nThe Fravix E-Library Team 📚"
            )
            mail.send(msg)

            flash('Joined group successfully. The admin has been notified.', 'success')
        else:

            admin_notification = Notification(
                user_id=group.created_by,
                sender_id=current_user.id,
                notification_type='join_request',
                msg=f'User {current_user.username} has requested to join your private group {group.name}.',
                is_read=False
            )
            db.session.add(admin_notification)
            db.session.commit()

            admin_email = User.query.get(group.created_by).email
            msg = Message(
                subject="Join Request Notification",
                recipients=[admin_email],
                body=f"Dear Group Admin,\n\n"
                     f"User {current_user.username} has requested to join your private group '{group.name}'.\n\n"
                     f"View all your groups here: {group_list_url}\n\n"
                     "Best regards,\nThe Fravix E-Library Team 📚"
            )
            mail.send(msg)

            flash('Join request sent', 'info')
    else:
        flash('Already requested to join or are a member of this group.', 'warning')

    return redirect(url_for('group_list'))

@app.route('/leave_group/<int:group_id>', methods=['POST'])
@login_required
def leave_group(group_id):
    group = Group.query.get_or_404(group_id)
    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group.id, is_approved=True).first()
    
    if membership:
        db.session.delete(membership)
        db.session.commit()
        flash('Left group successfully', 'info')
    else:
        flash('Not a member of the group.', 'warning')
    
    return redirect(url_for('group_list'))

@app.route('/approve_member/<int:membership_id>', methods=['POST'])
@login_required
def approve_member(membership_id):
    membership = GroupMembership.query.get_or_404(membership_id)
    group = Group.query.get(membership.group_id)

    if group.created_by != current_user.id:
        flash('Only the group admin can approve members', 'danger')
    else:
        membership.is_approved = True
        db.session.commit()

        user_notification = Notification(
            user_id=membership.user_id,
            sender_id=current_user.id,
            notification_type='approval',
            msg=f'Your request to join the group {group.name} has been approved.',
            is_read=False
        )
        db.session.add(user_notification)
        db.session.commit()

        user = User.query.get(membership.user_id)

        if user:
            group_list_url = url_for('group_list', _external=True)

            msg = Message(
                subject=f"Your request to join {group.name} has been approved",
                recipients=[user.email],
                body=f"Dear {user.username},\n\n"
                     f"Your request to join the group '{group.name}' has been approved by the group admin.\n\n"
                     f"You can view your groups here: {group_list_url}\n\n"
                    "Best regards,\nThe Fravix E-Library Team 📚"
        )
        mail.send(msg)

        flash('Member approved successfully', 'success')
    
    return redirect(url_for('group_chat', group_id=group.id))

@app.route('/reject_member/<int:membership_id>', methods=['POST'])
@login_required
def reject_member(membership_id):
    membership = GroupMembership.query.get_or_404(membership_id)
    group = membership.group
    
    if group.created_by != current_user.id:
        flash('Only the group admin can reject members', 'danger')
        return redirect(url_for('group_chat', group_id=group.id))
    else:
        db.session.delete(membership)
        db.session.commit()

        user_notification = Notification(
            user_id=membership.user_id,
            sender_id=current_user.id,
            notification_type='rejection',
            msg=f'Your request to join the group {group.name} has been rejected.',
            is_read=False
        )
        db.session.add(user_notification)
        db.session.commit()

        user = User.query.get(membership.user_id)

        if user:
            group_list_url = url_for('group_list', _external=True)

            msg = Message(
                subject=f"Your request to join {group.name} has been rejected",
                recipients=[user.email],
                body=f"Dear {user.username},\n\n"
                     f"Unfortunately, your request to join the group '{group.name}' has been rejected by the group admin.\n\n"
                     f"You can view all your groups here: {group_list_url}\n\n"
                     "Best regards,\nThe Fravix E-Library Team 📚"
        )
        mail.send(msg)

        flash('Member rejected and removed from the pending list', 'danger')

    return redirect(url_for('group_chat', group_id=group.id))

from sqlalchemy.orm import joinedload

@app.route('/remove_member/<int:group_id>/<int:user_id>', methods=['POST'])
@login_required
def remove_member(group_id, user_id):
    group = Group.query.get_or_404(group_id)

    if group.created_by != current_user.id:
        flash('You are not authorized to remove members from this group.', 'danger')
        return redirect(url_for('group_list'))

    membership = GroupMembership.query.options(joinedload(GroupMembership.user)).filter_by(group_id=group_id, user_id=user_id).first()
    
    if membership:
        db.session.delete(membership)
        db.session.commit()
        flash(f'User {membership.user.username} has been removed from the group.', 'success')
    else:
        flash('User not found in this group.', 'danger')
    
    return redirect(url_for('group_chat', group_id=group_id))

@app.route('/group/<int:group_id>')
@login_required
def group_chat(group_id):
    group = Group.query.get_or_404(group_id)

    if group.created_by == current_user.id:

        group_messages = GroupMessage.query.filter_by(group_id=group.id).order_by(GroupMessage.timestamp).all()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        return render_template('group_chat.html', group=group, group_messages=group_messages, unread_count=unread_count, notifications=notifications)

    membership = GroupMembership.query.filter_by(user_id=current_user.id, group_id=group.id).first()
    if not membership:
        flash('You are not a member of this group.', 'danger')
        return redirect(url_for('group_list'))
    
    if not membership.is_approved:
        flash('Access Denied. Please wait for approval.', 'danger')
        return redirect(url_for('group_list'))

    group_messages = GroupMessage.query.filter_by(group_id=group.id).order_by(GroupMessage.timestamp).all()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()

    return render_template('group_chat.html', group=group, group_messages=group_messages, unread_count=unread_count, notifications=notifications)

@app.route('/send/<int:group_id>', methods=['POST'])
@login_required
def send(group_id):

    content = request.form.get('content')
    
    if not content:
        flash("Message cannot be empty!", "warning")
        return redirect(url_for('group_chat', group_id=group_id))

    new_group_message = GroupMessage(user_id=current_user.id, group_id=group_id, content=content)
    db.session.add(new_group_message)
    db.session.commit()

    group_members = GroupMembership.query.filter_by(group_id=group_id).all()

    group = Group.query.get_or_404(group_id)
    admin_id = group.created_by

    for membership in group_members:
        if membership.user_id != current_user.id:

            notification_msg = f"New message in group '{new_group_message.group.name}' from {current_user.username}: {new_group_message.content}"

            notification = Notification(
                user_id=membership.user_id,
                sender_id=current_user.id,
                notification_type="group_message",
                msg=notification_msg,
                is_read=False
            )
            db.session.add(notification)

    if admin_id != current_user.id and admin_id not in [member.user_id for member in group_members]:
        admin_notification = Notification(
            user_id=admin_id,
            sender_id=current_user.id,
            notification_type="group_message",
            msg=f"New message in group '{new_group_message.group.name}' from {current_user.username}: {new_group_message.content}",
            is_read=False
        )
        db.session.add(admin_notification)

    db.session.commit()

    return redirect(url_for('group_chat', group_id=group_id))

@app.route('/group_chat_updates/<int:group_id>', methods=['GET'])
@login_required
def group_chat_updates(group_id):
    last_message_id = int(request.args.get('last_message_id', 0))
    new_messages = GroupMessage.query.filter(GroupMessage.group_id == group_id, GroupMessage.id > last_message_id).order_by(GroupMessage.timestamp).all()
    return jsonify([
        {
            'id': message.id,
            'user_id': message.user.id,
            'username': message.user.username,
            'content': message.content,
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        }
        for message in new_messages
    ])

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        college = request.form.get('college')
        branch = request.form.get('branch')
        bio = request.form.get('bio') 

        is_admin = request.form.get('is_admin') == 'yes'

        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != current_user.id:
            flash('This username is already taken. Please choose a different one.', 'danger')
            return redirect(request.url)  

        current_user.username = username
        current_user.college = college
        current_user.branch = branch
        current_user.bio = bio

        current_user.is_admin = is_admin

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile', user_id=current_user.id))  
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return render_template('edit_profile.html', user=current_user, unread_count=unread_count, notifications=notifications)

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    file_url = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)
    ratings = db.relationship('Rating', backref='resource', lazy=True)

    user = db.relationship('User', backref='resources')

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Integer, nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Favourite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from sqlalchemy import func

@app.route('/')
@login_required
def home():
    resources = Resource.query.order_by(Resource.timestamp.desc()).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    users = User.query.all() 
    all_products = Product.query.order_by(func.random()).limit(3).all()
    all_groups = Group.query.order_by(func.random()).limit(3).all()
    return render_template('home.html', resources=resources, unread_count=unread_count, notifications=notifications, products=all_products, groups=all_groups, users=users)

otp_storage = {}

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            flash('Please enter a valid email address.', 'danger')
            return redirect(request.url)

        existing_user_email = User.query.filter_by(email=email).first()
        if existing_user_email:
            flash('Email is already registered. Please use a different email.', 'danger')
            return redirect(request.url)

        existing_user_username = User.query.filter_by(username=username).first()
        if existing_user_username:
            flash('Username is already taken. Please choose a different username.', 'danger')
            return redirect(request.url)

        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_pattern, password):
            flash('Your password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character.', 'danger')
            return redirect(request.url)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    unread_count = 0
    notifications = []
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()

    return render_template('register.html', unread_count=unread_count, notifications=notifications)

@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.json['email']
    otp = random.randint(100000, 999999)
    otp_storage[email] = otp 
    print(f"Sending OTP {otp} to {email}") 

    msg = Message('Your OTP Code', recipients=[email])
    msg.body = f'Your OTP is {otp}. It is valid for the next 10 minutes.'
    mail.send(msg)

    return jsonify({"message": "OTP sent to your email."}), 200

@app.route('/validate_otp', methods=['POST'])
def validate_otp():
    email = request.json['email']
    otp = request.json['otp']

    if otp_storage.get(email) == int(otp):
        del otp_storage[email]  
        return jsonify({"message": "OTP validated successfully!"}), 200
    else:
        return jsonify({"message": "Invalid OTP."}), 400

@app.errorhandler(Exception)
def handle_error(error):
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = []

    app.logger.error(f"Error occurred: {error}")

    return render_template(
        'error.html', 
        unread_count=unread_count, 
        notifications=notifications
    ), 500 

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user:
            if user.active_session and user.active_session != request.remote_addr:
                send_login_notification(user, request.remote_addr)
                flash('You are already logged in from another device. Please check your email for details.', 'danger')
                return redirect(request.url)

            try:
                if bcrypt.check_password_hash(user.password, password):
                    user.active_session = request.remote_addr 
                    db.session.commit()
                    login_user(user)
                    send_login_notification(user, request.remote_addr)
                    flash('Logged in successfully.', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('Login failed. Check email and password.', 'danger')
            except ValueError as e:
                flash("There was an issue with your password. Please try resetting your password.", "danger")
                print(f"Password hash error: {e}")
        else:
            flash('Login failed. Check email and password.', 'danger')

    unread_count = 0
    notifications = []
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()

    return render_template('login.html', unread_count=unread_count, notifications=notifications)

def send_login_notification(user, remote_addr):
    msg = Message(
        subject="New Login Notification on Fravix E-Library!",
        recipients=[user.email],
        body=(
            f"Hello {user.username},\n\n"
            f"You have logged in to your Fravix E-Library account from a new device.\n\n"
            f"IP Address: {remote_addr}\n\n"
            "If this was not you, please change your password immediately and contact support.\n\n"
            "Thank you for being a part of Fravix E-Library.\n\n"
            "Best Regards,\n"
            "The Fravix E-Library Team 📚"
        )
    )
    mail.send(msg)
    
    new_notification = Notification(
        user_id=user.id,
        sender_id=user.id,  
        notification_type="login_alert",
        is_read=False
    )
    db.session.add(new_notification)
    db.session.commit()

@app.route('/logout')
@login_required
def logout():
    current_user.active_session = None  
    db.session.commit()  
    logout_user()
    flash('You have been logged out.', 'info')
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = []

    return redirect(url_for('login', unread_count=unread_count, notifications=notifications))

@app.before_request
def check_active_session():
    if current_user.is_authenticated:
        if current_user.active_session and current_user.active_session != request.remote_addr:
            logout_user()  
            flash('You have been logged out due to login from another device.', 'warning')
            return redirect(url_for('login'))

app.config['UPLOAD_FOLDER'] = 'uploads/'  
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'mp3', 'mp4', 'avi', 'mkv', 'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_url(url):
    url_pattern = re.compile(
        r'^(?:http|ftp)s?://'  
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' 
        r'localhost|' 
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  
        r'(?::\d+)?'  
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return re.match(url_pattern, url) is not None

from random import randint

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        title = request.form.get('subject')
        class_title = request.form.get('class_subject')
        description = request.form.get('description')
        year = request.form.get('year') 
        class_year = request.form.get('class_year')
        material_type = request.form.get('material_type')
        upload_option = request.form.get('upload_option')
        combined_year = class_year if class_year else year
        combined_title = class_title if class_title else title 
        if upload_option == 'file':
            if 'file' not in request.files:
                flash('No file part', 'danger')
                return redirect(request.url)

            file = request.files['file']

            if file.filename == '':
                flash('No selected file', 'danger')
                return redirect(request.url)

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)

                new_resource = Resource(
                    title = f"{combined_year} - {combined_title.title()} - ({material_type})",
                    description=description,
                    file_url=file_path,
                    user_id=current_user.id
                )
                db.session.add(new_resource)

                random_points = randint(1, 5)
                current_user.points += random_points 
                db.session.commit()

                flash(f'Resource uploaded successfully! You earned {random_points} points.', 'success')
                
                if current_user.points >= 100:
                    flash('Congratulations! You have earned 100 points.', 'success')

                return redirect(url_for('home'))

        elif upload_option == 'url':
            url = request.form.get('url')

            if not url or not is_valid_url(url):
                flash('Please provide a valid URL.', 'danger')
                return redirect(request.url)

            new_resource = Resource(
                title = f"{combined_year} - {combined_title.title()} - ({material_type})",
                description=description,
                file_url=url,
                user_id=current_user.id
            )
            db.session.add(new_resource)

            random_points = randint(1, 5)
            current_user.points += random_points 
            db.session.commit()

            flash(f'Resource uploaded successfully! You earned {random_points} points.', 'success')

            if current_user.points >= 100:
                flash('Congratulations! You have earned 100 points.', 'success')

            return redirect(url_for('home'))
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('upload.html', unread_count=unread_count, notifications=notifications)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if not bcrypt.check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(request.url)
        
        hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password = hashed_new_password
        
        db.session.commit() 
        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile', user_id=current_user.id)) 
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('change_password.html', unread_count=unread_count, notifications=notifications)

@app.route('/resource/<int:resource_id>', methods=['GET', 'POST'])
@login_required
def resource_detail(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    user_rating = Rating.query.filter_by(resource_id=resource.id, user_id=current_user.id).first()

    if request.method == 'POST':
        if 'rating' in request.form:
            if user_rating:
                flash('You can only rate this resource once.', 'warning')
            else:
                score = int(request.form.get('rating'))
                new_rating = Rating(score=score, resource_id=resource.id, user_id=current_user.id)
                db.session.add(new_rating)
                db.session.commit()
                flash('Rating submitted!', 'success')

        elif 'comment' in request.form:
            content = request.form.get('comment')
            new_comment = Comment(content=content, resource_id=resource.id, user_id=current_user.id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Comment added!', 'success')
            if resource.user_id != current_user.id:
                send_comment_notification(to_user_id=resource.user_id, commenter_username=current_user.username,
                                          resource_id=resource.id, is_reply=False)

        elif 'reply' in request.form:
            content = request.form.get('reply')
            comment_id = request.form.get('comment_id') 
            if comment_id: 
                comment = Comment.query.get(comment_id)
                if comment: 
                    new_reply = Reply(content=content, comment_id=comment_id, user_id=current_user.id)
                    db.session.add(new_reply)
                    db.session.commit()
                    flash('Reply added!', 'success')
                    if comment.user_id != current_user.id:
                        send_comment_notification(to_user_id=comment.user_id, commenter_username=current_user.username,
                                                  resource_id=resource.id, is_reply=True)
                else:
                    flash('Comment not found.', 'danger')
            else:
                flash('Comment ID is required.', 'danger')
        
    ratings = Rating.query.filter_by(resource_id=resource.id).all()
    total_score = sum(rating.score for rating in ratings)
    rating_count = len(ratings)
    uploader = User.query.get(resource.user_id)
    comments = Comment.query.filter_by(resource_id=resource.id).options(
        db.joinedload(Comment.user),
        db.joinedload(Comment.replies)
    ).all()
    fav = Favourite.query.filter_by(user_id=current_user.id, resource_id=resource.id).first() is not None
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    rater_usernames = {rating.user_id: User.query.get(rating.user_id) for rating in ratings}
    return render_template('resource.html', resource=resource, ratings=ratings, uploader=uploader,
                           user_rating=user_rating, total_score=total_score, rating_count=rating_count,
                           fav=fav, unread_count=unread_count, comments=comments, rater_usernames=rater_usernames, notifications=notifications)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    if comment.user_id == current_user.id:
        for reply in comment.replies:
            db.session.delete(reply)
        
        db.session.delete(comment)
        db.session.commit()
        flash('Comment and all associated replies deleted successfully!', 'success')
    else:
        flash('You are not authorized to delete this comment.', 'danger')
    
    return redirect(request.referrer)

@app.route('/delete_reply/<int:reply_id>', methods=['POST'])
@login_required
def delete_reply(reply_id):
    reply = Reply.query.get_or_404(reply_id)
    if reply.user_id == current_user.id:
        db.session.delete(reply)
        db.session.commit()
        flash('Reply deleted successfully!', 'success')
    else:
        flash('You are not authorized to delete this reply.', 'danger')
    return redirect(request.referrer)

def send_comment_notification(to_user_id, commenter_username, resource_id, is_reply=False):
    user = User.query.get(to_user_id)
    if not user:
        return 
    
    action = "replied to your comment" if is_reply else "commented on your resource"
    subject = f"New { 'reply' if is_reply else 'comment'} notification"

    notification = Notification(
        user_id=to_user_id,  
        sender_id=current_user.id, 
        notification_type="comment_reply" if is_reply else "comment",
        resource_id=resource_id,
    )
    db.session.add(notification)
    db.session.commit()   

    resource_link = url_for('resource_detail', resource_id=resource_id, _external=True)
    msg = Message(
        subject=subject,
        recipients=[user.email],
        body=(
            f"Hello {user.username},\n\n"
            f"{commenter_username} has {action}.\n\n"
            f"View the comment here: {resource_link}\n\n"
            "Thank you,\n"
            "Fravix E-Library Team"
        )
    )
    mail.send(msg)

class ProfileView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    viewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=datetime.utcnow)
    email_sent = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', foreign_keys=[user_id])
    viewer = db.relationship('User', foreign_keys=[viewer_id])

@app.route('/user_profile/<int:user_id>')
@login_required
def user_profile(user_id):
    user = User.query.get_or_404(user_id)
    resources = Resource.query.filter_by(user_id=user_id).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    products = Product.query.filter_by(user_id=user.id).all()
    groups = Group.query.filter_by(created_by=user.id).all()
    users = User.query.all() 

    if current_user.id != user_id:
        existing_view = ProfileView.query.filter(
            ProfileView.user_id == user_id,
            ProfileView.viewer_id == current_user.id,
            db.func.date(ProfileView.viewed_at) == datetime.utcnow().date()
        ).first()

        if not existing_view or not existing_view.email_sent:
            send_profile_view_notification(
                to_email=user.email,
                viewer_username=current_user.username,
                viewer_user_id=current_user.id
            )

            profile_view = ProfileView(
                user_id=user_id,
                viewer_id=current_user.id,
                email_sent=True
            )
            db.session.add(profile_view)

            notification = Notification(
                user_id=user_id,
                sender_id=current_user.id,
                notification_type="profile_view",
                is_read=False
            )
            db.session.add(notification)
            db.session.commit()
        else:
            existing_view.viewed_at = datetime.utcnow()
            db.session.commit()

    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('user_profile.html', user=user, resources=resources, unread_count=unread_count, notifications=notifications, products=products, groups=groups, users=users)

def send_profile_view_notification(to_email, viewer_username, viewer_user_id):
    viewer_profile_link = url_for('user_profile', user_id=viewer_user_id, _external=True)
    chat_link = url_for('chat', user_id=viewer_user_id, _external=True) 

    msg = Message(
        subject="Someone viewed your profile on Fravix E-Library!",
        recipients=[to_email],
        body=(f"Hello,\n\n"
              f"{viewer_username} just visited your profile on Fravix E-Library! 🎉\n\n"
              f"Check out their profile here: {viewer_profile_link}\n"
              f"Start a chat here: {chat_link}\n\n"
              "Don't miss out on connecting with them!\n\n"
              "Thank you for being a part of Fravix E-Library.\n\n"
              "Best Regards,\n"
              "The Fravix E-Library Team 📚")
    )
    mail.send(msg)

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    if current_user.is_authenticated:
        user = current_user  
        resources = Resource.query.filter_by(user_id=user.id).all()
        products = Product.query.filter_by(user_id=user.id).all()
        groups = Group.query.filter_by(created_by=user.id).all()
        groupss = Group.query.join(GroupMembership).filter(
            GroupMembership.user_id == current_user.id 
        ).filter(
            GroupMembership.is_admin == False  
        ).all()
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
        users = User.query.all() 
        return render_template('profile.html', user=user, resources=resources, unread_count=unread_count, notifications=notifications, products=products, groups=groups, users=users, groupss=groupss)
    else:
        flash('Please log in to access your profile.')
        return redirect(url_for('login'))

@app.route('/search', methods=['POST'])
def search():
    query = request.form.get('query')
    if query:
        results = Resource.query.filter(
            (Resource.title.ilike(f'%{query}%')) | 
            (Resource.description.ilike(f'%{query}%'))
        ).all()
    else:
        results = []

    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = []  

    return render_template('search.html', results=results, unread_count=unread_count, notifications=notifications)

@app.route('/recommendations')
@login_required
def recommendations():
    year_filter = request.args.get('year')
    subject_filter = request.args.get('subject')
    material_type_filter = request.args.get('material_type')

    query = Resource.query

    if year_filter:
        query = query.filter(Resource.title.contains(f"{year_filter}"))
    if subject_filter:
        query = query.filter(Resource.title.contains(subject_filter)) 
    if material_type_filter:
        query = query.filter(Resource.title.ilike(f'%{material_type_filter}%'))

    resources = query.order_by(Resource.views.desc()).limit(5).all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('recommendations.html', resources=resources, unread_count=unread_count, notifications=notifications)

@app.errorhandler(404)
def page_not_found(e):
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 
    
    return render_template('404.html', unread_count=unread_count, notifications=notifications), 404

@app.route('/favourite/<int:resource_id>')
@login_required
def favourite(resource_id):
    fav = Favourite.query.filter_by(user_id=current_user.id, resource_id=resource_id).first()
    
    if fav:
        db.session.delete(fav)
        db.session.commit()
        flash('Resource removed from favourites!', 'info')
    else:
        new_fav = Favourite(resource_id=resource_id, user_id=current_user.id)
        db.session.add(new_fav)
        db.session.commit()
        flash('Resource added to favourites!', 'success')
    
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return redirect(url_for('resource_detail', resource_id=resource_id, unread_count=unread_count, notifications=notifications))

@app.route('/my_favourites')
@login_required
def my_favourites():
    favs = Favourite.query.filter_by(user_id=current_user.id).all()
    favourite_resources = []

    for fav in favs:
        resource = Resource.query.get(fav.resource_id)
        if resource: 
            favourite_resources.append(resource)
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('home.html', resources=favourite_resources, unread_count=unread_count, notifications=notifications)

ADMIN_EMAIL = 'fravix@elibrary.com'
ADMIN_PASSWORD = 'fravix6708@'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials!', 'danger')

    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 

    return render_template('admin_login.html', unread_count=unread_count, notifications=notifications)

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    users = User.query.all()
    materials = Resource.query.all()
    products = Product.query.all()
    groups = Group.query.all()  
    pending_subscriptions = Subscription.query.all()

    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 

    return render_template('admin_dashboard.html', 
                           users=users, 
                           materials=materials, 
                           products=products, 
                           groups=groups,
                           unread_count=unread_count, 
                           notifications=notifications, subscriptions=pending_subscriptions)

@app.route('/delete_groups/<int:group_id>', methods=['POST'])
def delete_groups(group_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    group = Group.query.get(group_id)
    
    if group:
        try:

            group_memberships = GroupMembership.query.filter_by(group_id=group.id).all()
            for membership in group_memberships:
                db.session.delete(membership)

            group_messages = GroupMessage.query.filter_by(group_id=group.id).all()
            for message in group_messages:
                db.session.delete(message)

            db.session.delete(group)
            db.session.commit()
            
            flash('Group deleted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
    else:
        flash('Group not found.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/confirm_purchase/<int:request_id>', methods=['POST'])
@login_required
def confirm_purchase(request_id):
    purchase_request = PurchaseRequest.query.get(request_id)
    if purchase_request:
        purchase_request.status = 'Confirmed'
        db.session.commit()
        flash('Purchase request confirmed successfully!', 'success')

        product_link = url_for('product_detail', product_id=purchase_request.product.id, _external=True)

        buyer_email = purchase_request.buyer.email
        buyer_message = Message('Your Purchase Request Status: Confirmed',
                                sender='elibraryvgec@gmail.com',
                                recipients=[buyer_email])
        buyer_message.body = f"""Dear {purchase_request.buyer.username},

Your purchase request for '{purchase_request.product.item_name}' has been confirmed.

Product Details:
- Main Category: {purchase_request.product.main_category}
- Subcategory: {purchase_request.product.subcategory or 'N/A'}
- Detail: {purchase_request.product.detail or 'N/A'}
- Description: {purchase_request.product.description}
- Price: ${purchase_request.product.price}
- Condition: {purchase_request.product.condition}
- Brand: {purchase_request.product.brand or 'N/A'}
- Warranty: {purchase_request.product.warranty or 'N/A'}
- Contact Name: {purchase_request.product.contact_name}
- Contact Email: {purchase_request.product.contact_email}
- Contact Phone: {purchase_request.product.contact_phone}
- Location: {purchase_request.product.location or 'N/A'}
- Additional Information: {purchase_request.product.additional_info or 'N/A'}

Buyer's Information:
- Name: {purchase_request.buyer.username}
- Email: {purchase_request.buyer.email}
- Contact Number: {purchase_request.contact_number}

You can view the product here: {product_link}

Feel free to contact the uploader directly to finalize the purchase and arrange for the product pickup!

Best Regards,
The Fravix E-Library Team 📚
"""
        mail.send(buyer_message)

        uploader_email = purchase_request.product.user.email
        uploader_message = Message('Purchase Request Confirmed',
                                   sender='elibraryvgec@gmail.com',
                                   recipients=[uploader_email])
        uploader_message.body = f"""Dear {purchase_request.product.user.username},

The purchase request for your product '{purchase_request.product.item_name}' has been confirmed.

Product Details:
- Main Category: {purchase_request.product.main_category}
- Subcategory: {purchase_request.product.subcategory or 'N/A'}
- Detail: {purchase_request.product.detail or 'N/A'}
- Description: {purchase_request.product.description}
- Price: ${purchase_request.product.price}
- Condition: {purchase_request.product.condition}
- Brand: {purchase_request.product.brand or 'N/A'}
- Warranty: {purchase_request.product.warranty or 'N/A'}
- Contact Name: {purchase_request.product.contact_name}
- Contact Email: {purchase_request.product.contact_email}
- Contact Phone: {purchase_request.product.contact_phone}
- Location: {purchase_request.product.location or 'N/A'}
- Additional Information: {purchase_request.product.additional_info or 'N/A'}

Buyer's Information:
- Name: {purchase_request.buyer.username}
- Email: {purchase_request.buyer.email}
- Contact Number: {purchase_request.contact_number}

You can view the product here: {product_link}

Feel free to contact the buyer directly and arrange the purchase and product handover!   

Best Regards,
The Fravix E-Library Team 📚
"""
        mail.send(uploader_message)

    else:
        flash('Purchase request not found.', 'danger')

    return redirect(url_for('product_detail', product_id=purchase_request.product.id))

@app.route('/reject_purchase/<int:request_id>', methods=['POST'])
@login_required
def reject_purchase(request_id):
    purchase_request = PurchaseRequest.query.get(request_id)
    if purchase_request:
        purchase_request.status = 'Rejected'
        db.session.commit()
        flash('Purchase request rejected successfully!', 'danger')

        product_link = url_for('product_detail', product_id=purchase_request.product.id, _external=True)

        buyer_email = purchase_request.buyer.email
        buyer_message = Message('Your Purchase Request Status: Rejected',
                                sender='elibraryvgec@gmail.com',
                                recipients=[buyer_email])
        buyer_message.body = f"""Dear {purchase_request.buyer.username},

Your purchase request for '{purchase_request.product.item_name}' has been rejected.

You can view the product here: {product_link}

Best Regards,
The Fravix E-Library Team 📚
"""
        mail.send(buyer_message)

        uploader_email = purchase_request.product.user.email
        uploader_message = Message('Purchase Request Rejected',
                                   sender='elibraryvgec@gmail.com',
                                   recipients=[uploader_email])
        uploader_message.body = f"""Dear {purchase_request.product.user.username},

The purchase request for your product '{purchase_request.product.item_name}' has been rejected.

You can view the product here: {product_link}

Best Regards,
The Fravix E-Library Team 📚
"""
        mail.send(uploader_message)

    else:
        flash('Purchase request not found.', 'danger')

    return redirect(url_for('product_detail', product_id=purchase_request.product.id))

@app.route('/delete_products/<int:product_id>', methods=['POST'])
@login_required
def delete_products(product_id):
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    product = Product.query.get(product_id)
    if product:

        PurchaseRequest.query.filter_by(product_id=product.id).delete()

        db.session.delete(product)
        db.session.commit()
        flash('Product deleted successfully!', 'success')
    else:
        flash('Product not found.', 'danger')

    return redirect(url_for('admin_dashboard'))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)

    replies = db.relationship('Reply', backref='parent_comment', lazy=True, cascade='all, delete-orphan')
    user = db.relationship('User', backref='comments', lazy=True)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)  
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='replies')
    comment = db.relationship('Comment', backref='reply_comments')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Post {self.title}>'

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    title = request.form['title']
    description = request.form['description']

    new_post = Post(title=title, description=description)
    db.session.add(new_post)
    db.session.commit()
    flash('Post created successfully!', 'success')

    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 

    return redirect(url_for('admin_dashboard', unread_count=unread_count, notifications=notifications))

@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'admin_logged_in' not in session:
        flash('You are not authorized to delete this post.', 'danger')
        return redirect(url_for('posts'))  

    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully!', 'success')
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 
    return redirect(url_for('posts', unread_count=unread_count, notifications=notifications))

@app.route('/posts')
def posts():
    all_posts = Post.query.all()
    
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 
    
    return render_template('posts.html', posts=all_posts, unread_count=unread_count, notifications=notifications)

@app.route('/thanks')
@login_required
def thanks():
    materials = Resource.query.all()

    unique_materials = {}
    
    for material in materials:
        if material.user_id not in unique_materials:
            unique_materials[material.user_id] = material
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('thanks.html', materials=unique_materials.values(), unread_count=unread_count, notifications=notifications)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    try:
        ratings = Rating.query.filter_by(user_id=user_id).all()
        for rating in ratings:
            db.session.delete(rating) 

        user = User.query.get(user_id)
        if user:
            db.session.delete(user) 
            db.session.commit()  
            flash('User deleted successfully!', 'success')
        else:
            flash('User not found!', 'error')

    except Exception as e:
        db.session.rollback()  
        flash('Error occurred while deleting the user: {}'.format(e), 'error')
    
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return redirect(url_for('admin_dashboard', unread_count=unread_count, notifications=notifications))

@app.route('/delete_material/<int:material_id>', methods=['POST'])
@login_required 
def delete_material(material_id):
    material = Resource.query.get(material_id)

    if material:
        for rating in material.ratings:
            db.session.delete(rating)

        for fav in Favourite.query.filter_by(resource_id=material.id).all():
            db.session.delete(fav)

        db.session.delete(material)
        db.session.commit()
        flash('Material deleted successfully!', 'info')
    else:
        flash('Material not found.', 'danger')

    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return redirect(url_for('admin_dashboard', unread_count=unread_count, notifications=notifications))

@app.route('/faq')
def faq():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 

    return render_template('faq.html', unread_count=unread_count, notifications=notifications)

@app.route('/about')
def about():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 

    return render_template('about.html', unread_count=unread_count, notifications=notifications)

@app.route('/edit_resource/<int:resource_id>', methods=['GET', 'POST'])
@login_required
def edit_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    if resource.user_id != current_user.id:
        abort(403)  
    
    if request.method == 'POST':
        resource.description = request.form['description']
        resource.file_url = request.form['file_url']
        db.session.commit()
        flash('Resource updated successfully!', 'success')
        return redirect(url_for('resource_detail', resource_id=resource.id))
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('edit_resource.html', resource=resource, unread_count=unread_count, notifications=notifications)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class Notification(db.Model):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    message_id = db.Column(db.Integer, db.ForeignKey('chat_message.id'), nullable=True)  
    notification_type = db.Column(db.String(50), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    resource_id = db.Column(db.Integer, nullable=True)
    user = db.relationship('User', foreign_keys=[user_id])
    sender = db.relationship('User', foreign_keys=[sender_id])
    message = db.relationship('ChatMessage')
    msg = db.Column(db.String(255))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/chat/<int:user_id>', methods=['GET'])
@login_required
def chat(user_id):
    other_user = User.query.get(user_id)
    if not current_user.is_following(other_user) or not other_user.is_following(current_user):
        flash('You can only chat with users who have followed you back.', 'warning')
        return redirect(url_for('user_profile', user_id=user_id))
    messages = ChatMessage.query.filter( 
        (ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == user_id) |
        (ChatMessage.sender_id == user_id) & (ChatMessage.receiver_id == current_user.id)
    ).order_by(ChatMessage.timestamp).all()

    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    timezone_offset = timedelta(hours=5, minutes=30)
    for message in messages:
        message.local_timestamp = message.timestamp + timezone_offset

    return render_template('chat.html', other_user=other_user, messages=messages, unread_count=unread_count, notifications=notifications)

@app.route('/chat_updates/<int:user_id>', methods=['GET'])
@login_required
def chat_updates(user_id):
    last_message_id = request.args.get('last_message_id', type=int, default=0)

    new_messages = ChatMessage.query.filter(
        (
            (ChatMessage.sender_id == user_id) & (ChatMessage.receiver_id == current_user.id) |
            (ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == user_id)
        ) & (ChatMessage.id > last_message_id)
    ).order_by(ChatMessage.timestamp).all()

    timezone_offset = timedelta(hours=5, minutes=30)
    messages_data = []
    for message in new_messages:
        messages_data.append({
            'id': message.id,
            'sender_id': message.sender_id,
            'sender_username': message.sender.username,
            'content': message.content,
            'timestamp': (message.timestamp + timezone_offset).strftime('%Y-%m-%d %H:%M:%S')
        })

    return jsonify(messages_data)

@app.route('/send_email', methods=['POST'])
def send_email():
    subject = request.form['subject']
    message = request.form['message']
    
    users = User.query.all()

    for user in users:
        msg = Message(subject=subject,
                      sender='elibraryvgec@gmail.com',  
                      recipients=[user.email])
        msg.body = message
        try:
            mail.send(msg) 
        except Exception as e:
            flash(f"Failed to send email to {user.email}: {str(e)}", "danger")
            continue

    flash("Emails sent successfully!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/send_message/<int:user_id>', methods=['POST'], endpoint='send_chat_message')
@login_required
def send_message(user_id):
    content = request.form['message']
    
    message = ChatMessage(sender_id=current_user.id, receiver_id=user_id, content=content)
    db.session.add(message)
    db.session.commit()

    last_notification = Notification.query.filter_by(user_id=user_id, sender_id=current_user.id, notification_type='chat_message').order_by(Notification.id.desc()).first()

    if not last_notification or last_notification.created_at < datetime.utcnow() - timedelta(hours=1):
        notification = Notification(
            user_id=user_id, 
            sender_id=current_user.id, 
            message_id=message.id,           
            notification_type='chat_message'
        )
        db.session.add(notification)
        db.session.commit()

        send_chat_notification(user_id, current_user.username, content)

    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return redirect(url_for('chat', user_id=user_id, unread_count=unread_count, notifications=notifications))

def send_chat_notification(receiver_user_id, sender_username, message_content):
    receiver = User.query.get(receiver_user_id)
    if receiver and receiver.email:
        chat_link = url_for('chat', user_id=current_user.id, _external=True)
        
        msg = Message(
            subject=f"You have a new message from {sender_username}!",
            recipients=[receiver.email],
            body=(
                f"Dear User,\n\n"
                f"You have received a new message from {sender_username} on Fravix E-Library! ✉️\n\n"
                f"Message Content: {message_content}\n\n"
                f"You can view and reply to the message by clicking here: {chat_link}\n\n"
                "Feel free to reply and connect!\n\n"
                "Thank you for being a part of our community.\n\n"
                "Best Regards,\n"
                "The Fravix E-Library Team 📚"
            )
        )
        mail.send(msg)

@app.route('/notifications', methods=['GET'])
@login_required
def notifications():
    user_notifications = Notification.query.filter_by(user_id=current_user.id).all()

    for notification in user_notifications:
        notification.is_read = True

    db.session.commit()

    user_ids = set()
    messages = ChatMessage.query.filter( 
        (ChatMessage.sender_id == current_user.id) | (ChatMessage.receiver_id == current_user.id)
    ).all()

    for message in messages:
        if message.sender_id != current_user.id:
            user_ids.add(message.sender_id)
        else:
            user_ids.add(message.receiver_id)

    unique_users = User.query.filter(User.id.in_(user_ids)).all()

    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()

    notifications_list = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()

    return render_template('notifications.html', user_notifications=user_notifications, unique_users=unique_users, unread_count=unread_count, notifications=notifications_list)

@app.route('/delete_chat/<int:user_id>', methods=['POST'])
@login_required
def delete_chat(user_id):
    messages_to_delete = ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == user_id)) |
        ((ChatMessage.sender_id == user_id) & (ChatMessage.receiver_id == current_user.id))
    ).all()

    for message in messages_to_delete:
        Notification.query.filter_by(message_id=message.id).delete()

        db.session.delete(message)

    db.session.commit()

    flash('Chat deleted successfully.', 'success')
    return redirect(url_for('notifications'))

@app.route('/delete_all_notifications', methods=['POST'])
@login_required
def delete_all_notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).all()

    for notification in notifications:
        db.session.delete(notification)

    db.session.commit()

    flash('All notifications have been deleted.', 'success')

    return redirect(url_for('notifications'))

@app.route('/users')
@login_required 
def users_list():
    users = User.query.all()
    
    followed_users = []
    if current_user.is_authenticated:
        followed_users = current_user.followed.all()  
    
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('users_list.html', users=users, followed_users=followed_users, unread_count=unread_count, notifications=notifications)

from flask import redirect, url_for
from flask_login import current_user, login_required

@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    user_to_follow = User.query.get(user_id)
    if not user_to_follow:
        return jsonify({"error": "User not found."}), 404

    if current_user.is_following(user_to_follow):
        return jsonify({"message": "You are already following this user."}), 200

    current_user.follow(user_to_follow)

    try:
        notification = Notification(
            user_id=user_id,               
            sender_id=current_user.id,     
            message_id=None,                
            notification_type='follow',    
            is_read=False                   
        )
        db.session.add(notification)
        db.session.commit()

        send_follow_notification(user_to_follow.email, current_user.username, current_user.id)

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500  

    return redirect(url_for('user_profile', user_id=user_id))

def send_follow_notification(to_email, follower_username, follower_user_id):
    follower_profile_link = url_for('user_profile', user_id=follower_user_id, _external=True)
    msg = Message(
        subject=f"You have a new follower: {follower_username}!",
        recipients=[to_email],
        body=(
            f"Dear User,\n\n"
            f"We are excited to inform you that {follower_username} has started following you on Fravix E-Library! 🎉\n\n"
            f"You can view their profile here: {follower_profile_link}\n\n"
            "Feel free to connect and explore more!\n\n"
            "Thank you for being a part of our community.\n\n"
            "Best Regards,\n"
            "The Fravix E-Library Team 📚"
        )
    )
    mail.send(msg)

@app.route('/unfollow/<int:user_id>', methods=['POST'])
@login_required
def unfollow_user(user_id):
    user = User.query.get_or_404(user_id)
    if user is not current_user:
        current_user.unfollow(user)
        db.session.commit()
    return redirect(url_for('user_profile', user_id=user.id))

@app.route('/followers/<int:user_id>')
@login_required
def followers(user_id):
    user = User.query.get_or_404(user_id)
    followers = user.followers.all()  
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('followers_list.html', user=user, followers=followers, unread_count=unread_count, notifications=notifications)

@app.route('/following/<int:user_id>')
@login_required
def following(user_id):
    user = User.query.get_or_404(user_id)
    following = user.followed.all() 
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('following_list.html', user=user, following=following, unread_count=unread_count, notifications=notifications)

@app.route('/verify_account')
@login_required
def verify_account():
    if current_user.is_verified:
        flash('Your account is already verified!', 'info')
        return redirect(url_for('profile', user_id=current_user.id))
    
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('verify_account.html', user=current_user, otp_sent=False, unread_count=unread_count, notifications=notifications)

@app.route('/send_otps', methods=['POST'])
@login_required
def send_otps():
    email = request.form['email']
    otp = random.randint(100000, 999999) 
    session['otp'] = otp 
    
    msg = Message('Your OTP Code', sender='elibraryvgec@gmail.com', recipients=[email])
    msg.body = f'Your OTP code is {otp}. It is valid for 10 minutes.'
    mail.send(msg)
    
    flash('An OTP has been sent to your email.', 'info')
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    return render_template('verify_account.html', user=current_user, otp_sent=True, unread_count=unread_count, notifications=notifications)

@app.route('/verify_otps', methods=['POST'])
@login_required
def verify_otps():
    otp_entered = request.form['otp']
    if 'otp' in session and str(session['otp']) == otp_entered:
        current_user.is_verified = True
        db.session.commit()

        session.pop('otp', None)

        flash('Your account has been successfully verified!', 'success')

        return redirect(url_for('profile', user_id=current_user.id)) 
    else:
        flash('Invalid OTP. Please try again.', 'danger')
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
        return render_template('verify_account.html', user=current_user, otp_sent=True, unread_count=unread_count, notifications=notifications)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    otp_code = db.Column(db.String(6), nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    @staticmethod
    def generate_otp(user):
        otp_code = f"{random.randint(100000, 999999)}"
        expiration = datetime.utcnow() + timedelta(minutes=10)
        otp = OTP(otp_code=otp_code, expiration=expiration, user_id=user.id)
        db.session.add(otp)
        db.session.commit()
        return otp_code

@app.route('/forgot_password')
def forgot_password():
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 
    return render_template('forgot_password.html', unread_count=unread_count, notifications=notifications)

@app.route('/sends_otp', methods=['POST'])
def sends_otp():
    email = request.form.get('email')
    user = User.query.filter_by(email=email).first()

    if not user:
        flash("No account found with that email. Please register first.")
        return redirect(url_for('forgot_password'))

    otp_code = OTP.generate_otp(user)
    msg = Message("Your OTP for Password Reset", recipients=[user.email])
    msg.body = f"Your OTP code is {otp_code}. It is valid for 10 minutes."
    mail.send(msg)

    flash("An OTP has been sent to your email.")
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 
    return render_template('forgot_password.html', email=email, show_otp_form=True, unread_count=unread_count, notifications=notifications)

@app.route('/verifys_otp', methods=['POST'])
def verifys_otp():
    email = request.form.get('email')
    entered_otp = request.form.get('otp')
    user = User.query.filter_by(email=email).first()

    otp_record = OTP.query.filter_by(user_id=user.id, otp_code=entered_otp, is_used=False).first()

    if not otp_record or otp_record.expiration < datetime.utcnow():
        flash("Invalid or expired OTP. Please try again.")
        return redirect(url_for('forgot_password'))

    otp_record.is_used = True
    db.session.commit()
    flash("OTP verified! Please enter your new password.")
    if current_user.is_authenticated:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()
    else:
        unread_count = 0
        notifications = [] 
    return render_template('forgot_password.html', email=email, show_reset_form=True, unread_count=unread_count, notifications=notifications)

@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form.get('email')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash("Passwords do not match. Please try again.")
        return render_template('forgot_password.html', email=email, show_reset_form=True)

    if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', new_password):
        flash("Password must contain at least 8 characters, including uppercase, lowercase, number, and special character.")
        return render_template('forgot_password.html', email=email, show_reset_form=True)

    user = User.query.filter_by(email=email).first()
    
    if user is not None:
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()

        send_password_reset_email(user.email)
        create_password_reset_notification(user)

        flash("Password reset successfully! You can now log in with your new password.")
    else:
        flash("User not found.")
        return redirect(url_for('forgot_password'))

    return redirect(url_for('login'))

def send_password_reset_email(email):
    msg = Message(
        subject="Password Reset Confirmation",
        recipients=[email],
        body=(
            "Hello,\n\n"
            "Your password has been successfully reset. You can now log in with your new password.\n\n"
            "If you did not request this change, please contact support immediately.\n\n"
            "Best Regards,\n"
            "The Fravix E-Library Team"
        )
    )
    mail.send(msg)

def create_password_reset_notification(user):
    if not isinstance(user, User):
        print("Error: 'user' is not a User instance")
        return

    try:
        notification = Notification(
            user_id=user.id,
            sender_id=user.id, 
            notification_type="password_reset",
            msg="Your password was successfully reset."
        )
        db.session.add(notification)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error creating notification: {e}")
        
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    main_category = db.Column(db.String(150), nullable=False)
    subcategory = db.Column(db.String(150), nullable=False)
    detail = db.Column(db.String(150), nullable=False)
    item_name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    condition = db.Column(db.String(50), nullable=False)
    brand = db.Column(db.String(100), nullable=True)
    warranty = db.Column(db.String(100), nullable=True)
    item_image = db.Column(db.String(100), nullable=False)
    contact_name = db.Column(db.String(150), nullable=False)
    contact_email = db.Column(db.String(150), nullable=False)
    contact_phone = db.Column(db.String(15), nullable=False)
    location = db.Column(db.String(150), nullable=True)
    additional_info = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='Available')
    purchase_requests = db.relationship('PurchaseRequest', backref='product', lazy=True)

class PurchaseRequest(db.Model):
    __tablename__ = 'purchase_requests'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id', ondelete='CASCADE'), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    buyer = db.relationship('User', backref='purchase_requests')
    contact_number = db.Column(db.String(15), nullable=True)
    status = db.Column(db.String(50), default='Pending')
    buyer = db.relationship('User', backref='purchase_requests')

@app.route('/products')
@login_required
def products():
    all_products = Product.query.all()
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all() 
    return render_template('products.html', products=all_products, unread_count=unread_count, notifications=notifications)

@app.route('/product/<int:product_id>')
@login_required
def product_detail(product_id):

    product = Product.query.get_or_404(product_id)
    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all() 
    user = User.query.get(product.user_id)
    return render_template('product_detail.html', product=product, unread_count=unread_count, notifications=notifications, user=user)

@app.route('/mark_out_of_stock/<int:product_id>', methods=['POST'])
@login_required
def mark_out_of_stock(product_id):
    product = Product.query.get_or_404(product_id)
    if current_user.id != product.user_id:
        flash("You are not authorized to perform this action.", "danger")
        return redirect(url_for('product_detail', product_id=product.id))

    product.status = 'Out of Stock'
    db.session.commit()

    flash("Product marked as Out of Stock.", "success")
    return redirect(url_for('product_detail', product_id=product.id))

@app.route('/mark_in_stock/<int:product_id>', methods=['POST'])
@login_required
def mark_in_stock(product_id):
    product = Product.query.get_or_404(product_id)
    if current_user.id != product.user_id:
        flash("You are not authorized to perform this action.", "danger")
        return redirect(url_for('product_detail', product_id=product.id))

    product.status = 'Available'
    db.session.commit()

    flash("Product marked as Available and in stock.", "success")
    return redirect(url_for('product_detail', product_id=product.id))

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    try:

        product = Product.query.get_or_404(product_id)

        if current_user.id != product.user_id:
            flash("You are not authorized to perform this action.", "danger")
            return redirect(url_for('product_detail', product_id=product.id))

        PurchaseRequest.query.filter_by(product_id=product.id).delete()

        db.session.delete(product)
        db.session.commit()
        
        flash("Product deleted successfully.", "success")
        return redirect(url_for('products'))
    except IntegrityError as e:
        db.session.rollback()
        flash("A database error occurred while deleting the product.", "danger")
        print(f"IntegrityError: {e}")
        return redirect(url_for('product_detail', product_id=product.id))
    except Exception as e:
        db.session.rollback()
        flash("An unexpected error occurred. Please try again later.", "danger")
        print(f"Unexpected Error: {e}")
        return redirect(url_for('product_detail', product_id=product.id))

@app.route('/purchase/<int:product_id>', methods=['POST'])
@login_required
def purchase_product(product_id):

    product = Product.query.get_or_404(product_id)
    uploader = User.query.filter_by(id=product.user_id).first()

    if current_user.id == product.user_id:
        flash("You cannot purchase your own product!", "warning")
        return redirect(url_for('product_detail', product_id=product.id))

    contact_number = request.form.get('contact_number')

    if not contact_number:
        flash("You must provide your contact number to complete the purchase.", "warning")
        return redirect(url_for('product_detail', product_id=product.id))

    purchase_request = PurchaseRequest(
        product_id=product_id,
        buyer_id=current_user.id,
        contact_number=contact_number,
        status='Pending'
    )
    db.session.add(purchase_request)
    db.session.commit()

    user_request = PurchaseRequest.query.filter_by(product_id=product.id, buyer_id=current_user.id).first()

    product_link = url_for('product_detail', product_id=product.id, _external=True)

    subject_uploader = f"Product Inquiry: {product.item_name}"
    sender_email = "elibraryvgec@gmail.com"
    recipient_email_uploader = uploader.email

    body_uploader = f"""
Hello {uploader.username},

A user is interested in purchasing your product: {product.item_name}.

Product Details:
- Main Category: {product.main_category}
- Subcategory: {product.subcategory or 'N/A'}
- Detail: {product.detail or 'N/A'}
- Description: {product.description}
- Price: ${product.price}
- Condition: {product.condition}
- Brand: {product.brand or 'N/A'}
- Warranty: {product.warranty or 'N/A'}
- Contact Name: {product.contact_name}
- Contact Email: {product.contact_email}
- Contact Phone: {product.contact_phone}
- Location: {product.location or 'N/A'}
- Additional Information: {product.additional_info or 'N/A'}

Buyer's Information:
- Name: {current_user.username}
- Email: {current_user.email}
- Contact Number: {contact_number}

You can view the product here: {product_link}

Please visit the product page to review the purchase request and take appropriate action. You can confirm or reject the request directly from the product page. This will help keep the transaction process smooth and transparent for both the buyer and the seller.

Feel free to contact the buyer directly and arrange the purchase and product handover!    

Best regards,
The Fravix E-Library Team 📚
"""

    subject_buyer = f"Purchase Confirmation: {product.item_name}"
    recipient_email_buyer = current_user.email

    body_buyer = f"""
Hello {current_user.username},

Thank you for your interest in purchasing the following product:

Product Details:
- Main Category: {product.main_category}
- Subcategory: {product.subcategory or 'N/A'}
- Detail: {product.detail or 'N/A'}
- Description: {product.description}
- Price: ${product.price}
- Condition: {product.condition}
- Brand: {product.brand or 'N/A'}
- Warranty: {product.warranty or 'N/A'}
- Contact Name: {product.contact_name}
- Contact Email: {product.contact_email}
- Contact Phone: {product.contact_phone}
- Location: {product.location or 'N/A'}
- Additional Information: {product.additional_info or 'N/A'}

Buyer's Information:
- Name: {current_user.username}
- Email: {current_user.email}
- Contact Number: {contact_number}

You can view the product here: {product_link}

We are currently reviewing your request, and the status will be updated as soon as the admin confirms or rejects it. Please note that you will receive an email notification regarding the outcome of your request, and the product status will also be updated on the website.

Feel free to contact the uploader directly to finalize the purchase and arrange for the product pickup!

Best regards,
The Fravix E-Library Team 📚
"""

    try:

        msg_uploader = Message(subject_uploader, sender=sender_email, recipients=[recipient_email_uploader])
        msg_uploader.body = body_uploader
        mail.send(msg_uploader)

        msg_buyer = Message(subject_buyer, sender=sender_email, recipients=[recipient_email_buyer])
        msg_buyer.body = body_buyer
        mail.send(msg_buyer)

        flash("Purchase request sent successfully to both parties!", "success")
    except Exception as e:
        flash(f"An error occurred while sending the email: {e}", "danger")

    return redirect(url_for('product_detail', product_id=product.id, user_request=user_request))

import logging

logging.basicConfig(level=logging.DEBUG)

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if product.user_id != current_user.id:
        flash('You do not have permission to edit this product.', 'danger')
        return redirect(url_for('product_detail', product_id=product.id))

    if request.method == 'POST':

        product.item_name = request.form['itemName']
        product.description = request.form['description']
        product.price = request.form['price']
        product.condition = request.form['condition']
        product.brand = request.form['brand'] if request.form['brand'] else 'N/A'
        product.warranty = request.form['warranty'] if request.form['warranty'] else 'N/A'
        product.location = request.form['location'] if request.form['location'] else 'N/A'
        product.additional_info = request.form['additionalInfo'] if request.form['additionalInfo'] else 'N/A'

        db.session.commit()

        flash('Product updated successfully!', 'success')
        return redirect(url_for('product_detail', product_id=product.id))

    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all() 
    return render_template('edit_product.html', product=product, unread_count=unread_count, notifications=notifications)

@app.route('/upload_item', methods=['GET', 'POST'])
@login_required
def upload_item():
    if request.method == 'POST':
        try:
            user_subscription = Subscription.query.filter_by(user_id=current_user.id).first()

            if user_subscription is None or user_subscription.expiry_date < datetime.utcnow() or current_user.subscription_status != 'Active':

                existing_product_count = Product.query.filter_by(user_id=current_user.id).count()
                if existing_product_count >= 10:
                    return jsonify({"success": False, "message": "You can only upload Ten product unless your subscription is approved. To upload unlimited products, ensure your subscription is active and approved. Subscribe here: https://fravix.onrender.com/subscribe"})

            if 'itemImage' not in request.files:
                return jsonify({"success": False, "message": "No file part"})
            
            item_image = request.files['itemImage']
            if item_image.filename == '':
                return jsonify({"success": False, "message": "No selected file"})

            main_category = request.form['mainCategory']
            subcategory = request.form['subcategory']
            detail = request.form['detail']
            item_name = request.form['itemName']
            description = request.form['description']
            price = request.form['price']
            condition = request.form['condition']
            brand = request.form.get('brand', '')
            warranty = request.form.get('warranty', '')
            contact_name = request.form['contactName']
            contact_email = request.form['contactEmail']
            contact_phone = request.form['contactPhone']
            location = request.form.get('location', '')
            additional_info = request.form.get('additionalInfo', '')

            filename = secure_filename(item_image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            item_image.save(image_path)

            new_product = Product(
                main_category=main_category,
                subcategory=subcategory,
                detail=detail,
                item_name=item_name,
                description=description,
                price=price,
                condition=condition,
                brand=brand,
                warranty=warranty,
                item_image=filename,
                contact_name=contact_name,
                contact_email=contact_email,
                contact_phone=contact_phone,
                location=location,
                additional_info=additional_info,
                status='Available',
                user_id=current_user.id
            )

            db.session.add(new_product)
            db.session.commit()

            return jsonify({"success": True, "message": "Product uploaded successfully!"})

        except Exception as e:

            logging.error(f"Error uploading product: {str(e)}")
            db.session.rollback()
            return jsonify({"success": False, "message": f"Error uploading product: {str(e)}"})

    unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.id.desc()).limit(10).all()  
    return render_template('upload_item.html', unread_count=unread_count, notifications=notifications)

@app.context_processor
def inject_total_users():
    total_users = User.query.count()
    return dict(total_users=total_users)

@app.before_request
def create_tables():
    if not hasattr(app, 'db_created'):
        db.create_all()
        app.db_created = True

@app.route('/ads.txt')
def serve_ads_txt():
    return send_from_directory(os.getcwd(), 'ads.txt')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
