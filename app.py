from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os
import secrets
from sqlalchemy import or_, func, desc

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///twitter_clone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'posts'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    bio = db.Column(db.String(500))
    profile_picture = db.Column(db.String(200), default='default.jpg')
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')
    
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

    def get_unread_message_count(self):
        return Message.query.filter_by(receiver_id=self.id, is_read=False).count()

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    likes = db.relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    hashtags = db.relationship('PostHashtag', backref='post', lazy='dynamic', cascade='all, delete-orphan')

    def like_count(self):
        return self.likes.count()

    def comment_count(self):
        return self.comments.count()

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(200))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Hashtag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(100), unique=True, nullable=False)
    count = db.Column(db.Integer, default=1)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)

class PostHashtag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    hashtag_id = db.Column(db.Integer, db.ForeignKey('hashtag.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need admin privileges to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}

def extract_hashtags(content):
    import re
    return re.findall(r'#(\w+)', content)

def extract_mentions(content):
    import re
    return re.findall(r'@(\w+)', content)

def process_content(content):
    import re
    content = re.sub(r'#(\w+)', r'<a href="/hashtag/\1" class="text-primary">#\1</a>', content)
    content = re.sub(r'@(\w+)', r'<a href="/profile/\1" class="text-info">@\1</a>', content)
    return content

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('signup'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            user.is_online = True
            db.session.commit()
            return redirect(url_for('feed'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    current_user.is_online = False
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

@app.route('/feed')
@login_required
def feed():
    page = request.args.get('page', 1, type=int)
    followed_users = current_user.followed.all()
    followed_ids = [u.id for u in followed_users] + [current_user.id]
    
    posts = Post.query.filter(Post.user_id.in_(followed_ids)).order_by(Post.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    
    trending = Hashtag.query.order_by(Hashtag.count.desc()).limit(5).all()
    suggestions = User.query.filter(User.id != current_user.id).filter(~User.id.in_(followed_ids)).limit(5).all()
    
    return render_template('feed.html', posts=posts, trending=trending, suggestions=suggestions)

@app.route('/post', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content')
    image = request.files.get('image')
    
    if not content and not image:
        flash('Post cannot be empty.', 'danger')
        return redirect(url_for('feed'))
    
    post = Post(content=content or '', user_id=current_user.id)
    
    if image and allowed_file(image.filename):
        filename = secure_filename(f"{secrets.token_hex(8)}_{image.filename}")
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], 'posts', filename))
        post.image = filename
    
    db.session.add(post)
    db.session.flush()  # Get post ID
    
    # Process hashtags
    hashtags = extract_hashtags(content or '')
    for tag in hashtags:
        existing = Hashtag.query.filter_by(tag=tag).first()
        if existing:
            existing.count += 1
            existing.last_used = datetime.utcnow()
        else:
            existing = Hashtag(tag=tag)
            db.session.add(existing)
            db.session.flush()
        
        # Link hashtag to post
        post_hashtag = PostHashtag(post_id=post.id, hashtag_id=existing.id)
        db.session.add(post_hashtag)
    
    # Process mentions
    mentions = extract_mentions(content or '')
    for username in mentions:
        mentioned_user = User.query.filter_by(username=username).first()
        if mentioned_user and mentioned_user.id != current_user.id:
            notif = Notification(
                user_id=mentioned_user.id,
                content=f"{current_user.username} mentioned you in a post",
                link=f"/post/{post.id}"
            )
            db.session.add(notif)
    
    db.session.commit()
    flash('Post created successfully!', 'success')
    return redirect(url_for('feed'))

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.desc()).all()
    return render_template('post.html', post=post, comments=comments)

@app.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
        
        if existing_like:
            db.session.delete(existing_like)
            liked = False
        else:
            like = Like(user_id=current_user.id, post_id=post_id)
            db.session.add(like)
            
            if post.author.id != current_user.id:
                notif = Notification(
                    user_id=post.author.id,
                    content=f"{current_user.username} liked your post",
                    link=f"/post/{post_id}"
                )
                db.session.add(notif)
            liked = True
        
        db.session.commit()
        
        # Re-query to get updated count
        post = Post.query.get(post_id)
        return jsonify({
            'status': 'liked' if liked else 'unliked', 
            'count': post.like_count()
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def comment_post(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form.get('content')
    
    if not content:
        flash('Comment cannot be empty.', 'danger')
        return redirect(url_for('view_post', post_id=post_id))
    
    comment = Comment(content=content, user_id=current_user.id, post_id=post_id)
    db.session.add(comment)
    
    if post.author.id != current_user.id:
        notif = Notification(
            user_id=post.author.id,
            content=f"{current_user.username} commented on your post",
            link=f"/post/{post_id}"
        )
        db.session.add(notif)
    
    db.session.commit()
    flash('Comment added!', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.created_at.desc()).all()
    
    total_likes = sum(post.like_count() for post in posts)
    
    # Check if current user is following this user
    is_following = current_user.is_following(user) if current_user.is_authenticated else False
    
    return render_template('profile.html', user=user, posts=posts, total_likes=total_likes, is_following=is_following)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.bio = request.form.get('bio')
        current_user.location = request.form.get('location')
        current_user.website = request.form.get('website')
        
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{current_user.id}_profile_{secrets.token_hex(8)}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', filename))
                current_user.profile_picture = filename
        
        if 'cover_picture' in request.files:
            file = request.files['cover_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{current_user.id}_cover_{secrets.token_hex(8)}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'covers', filename))
                current_user.cover_picture = filename
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile', username=current_user.username))
    
    return render_template('edit_profile.html')

@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        if user.id == current_user.id:
            return jsonify({'error': 'Cannot follow yourself'}), 400
        
        if current_user.is_following(user):
            current_user.unfollow(user)
            status = 'unfollowed'
        else:
            current_user.follow(user)
            
            notif = Notification(
                user_id=user.id,
                content=f"{current_user.username} started following you",
                link=f"/profile/{current_user.username}"
            )
            db.session.add(notif)
            status = 'followed'
        
        db.session.commit()
        return jsonify({'status': status})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    
    users = User.query.filter(
        or_(User.username.contains(query), User.bio.contains(query))
    ).limit(20).all()
    
    hashtag_posts = []
    if query.startswith('#'):
        tag = query[1:]
        hashtag = Hashtag.query.filter_by(tag=tag).first()
        if hashtag:
            posts_with_tag = Post.query.join(PostHashtag).filter(PostHashtag.hashtag_id == hashtag.id).order_by(Post.created_at.desc()).limit(20).all()
            hashtag_posts = posts_with_tag
    else:
        posts_with_content = Post.query.filter(Post.content.contains(query)).order_by(Post.created_at.desc()).limit(20).all()
        hashtag_posts = posts_with_content
    
    return render_template('search.html', query=query, users=users, posts=hashtag_posts)

@app.route('/hashtag/<tag>')
@login_required
def hashtag(tag):
    hashtag_obj = Hashtag.query.filter_by(tag=tag).first()
    if not hashtag_obj:
        flash('No posts found with this hashtag.', 'info')
        return redirect(url_for('feed'))
    
    posts = Post.query.join(PostHashtag).filter(PostHashtag.hashtag_id == hashtag_obj.id).order_by(Post.created_at.desc()).all()
    
    return render_template('hashtag.html', tag=tag, posts=posts, hashtag=hashtag_obj)

@app.route('/notifications')
@login_required
def notifications():
    notifs = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    
    # Mark as read
    for notif in notifs:
        notif.is_read = True
    db.session.commit()
    
    return render_template('notifications.html', notifications=notifs)

@app.route('/messages')
@login_required
def messages():
    # Get all conversations
    sent_conversations = db.session.query(Message.receiver_id).filter(Message.sender_id == current_user.id).distinct()
    received_conversations = db.session.query(Message.sender_id).filter(Message.receiver_id == current_user.id).distinct()
    
    all_conversation_ids = set([id[0] for id in sent_conversations] + [id[0] for id in received_conversations])
    
    conversations = []
    for user_id in all_conversation_ids:
        if user_id != current_user.id:
            user = User.query.get(user_id)
            if user:
                last_message = Message.query.filter(
                    or_(
                        (Message.sender_id == current_user.id) & (Message.receiver_id == user_id),
                        (Message.sender_id == user_id) & (Message.receiver_id == current_user.id)
                    )
                ).order_by(Message.created_at.desc()).first()
                
                unread_count = Message.query.filter_by(sender_id=user_id, receiver_id=current_user.id, is_read=False).count()
                
                conversations.append({
                    'user': user,
                    'last_message': last_message,
                    'unread_count': unread_count
                })
    
    # Sort by last message time
    conversations.sort(key=lambda x: x['last_message'].created_at if x['last_message'] else datetime.min, reverse=True)
    
    return render_template('messages.html', conversations=conversations)

@app.route('/messages/search')
@login_required
def message_search():
    query = request.args.get('q', '')
    
    if query:
        # Search for users to message
        users = User.query.filter(
            User.username.contains(query),
            User.id != current_user.id
        ).limit(10).all()
        
        return jsonify({
            'users': [{
                'id': user.id,
                'username': user.username,
                'profile_picture': user.profile_picture,
                'is_online': user.is_online
            } for user in users]
        })
    
    return jsonify({'users': []})

@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def conversation(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        content = request.form.get('content')
        if not content:
            flash('Message cannot be empty.', 'danger')
            return redirect(url_for('conversation', user_id=user_id))
        
        message = Message(sender_id=current_user.id, receiver_id=user.id, content=content)
        db.session.add(message)
        
        notif = Notification(
            user_id=user.id,
            content=f"{current_user.username} sent you a message",
            link=f"/messages/{current_user.id}"
        )
        db.session.add(notif)
        db.session.commit()
        
        return redirect(url_for('conversation', user_id=user_id))
    
    # Get messages between current user and the other user
    messages = Message.query.filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.receiver_id == user.id),
            (Message.sender_id == user.id) & (Message.receiver_id == current_user.id)
        )
    ).order_by(Message.created_at).all()
    
    # Mark received messages as read
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
    
    db.session.commit()
    
    return render_template('conversation.html', user=user, messages=messages)

@app.route('/api/messages/<int:user_id>')
@login_required
def get_messages(user_id):
    user = User.query.get_or_404(user_id)
    
    messages = Message.query.filter(
        or_(
            (Message.sender_id == current_user.id) & (Message.receiver_id == user.id),
            (Message.sender_id == user.id) & (Message.receiver_id == current_user.id)
        )
    ).order_by(Message.created_at).all()
    
    # Mark received messages as read
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
    
    db.session.commit()
    
    return jsonify({
        'messages': [{
            'id': msg.id,
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'content': msg.content,
            'is_read': msg.is_read,
            'created_at': msg.created_at.isoformat(),
            'sender_username': msg.sender.username,
            'sender_profile_picture': msg.sender.profile_picture
        } for msg in messages]
    })

@app.route('/api/messages/send', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.get_json()
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        
        if not content or not receiver_id:
            return jsonify({'error': 'Message content and receiver are required'}), 400
        
        receiver = User.query.get(receiver_id)
        if not receiver:
            return jsonify({'error': 'User not found'}), 404
        
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            content=content
        )
        
        db.session.add(message)
        
        # Create notification for receiver
        notif = Notification(
            user_id=receiver_id,
            content=f"{current_user.username} sent you a message",
            link=f"/messages/{current_user.id}"
        )
        db.session.add(notif)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': {
                'id': message.id,
                'sender_id': message.sender_id,
                'receiver_id': message.receiver_id,
                'content': message.content,
                'is_read': message.is_read,
                'created_at': message.created_at.isoformat(),
                'sender_username': current_user.username,
                'sender_profile_picture': current_user.profile_picture
            }
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/trending')
@login_required
def trending():
    # Get trending hashtags
    hashtags = Hashtag.query.order_by(Hashtag.count.desc()).limit(20).all()
    
    # Get trending posts (most liked in last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    trending_posts = db.session.query(Post).join(Like).filter(
        Post.created_at >= yesterday
    ).group_by(Post.id).order_by(func.count(Like.id).desc()).limit(20).all()
    
    return render_template('trending.html', hashtags=hashtags, posts=trending_posts)

# Admin Panel Routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_posts = Post.query.count()
    total_likes = Like.query.count()
    total_comments = Comment.query.count()
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_posts = Post.query.order_by(Post.created_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_posts=total_posts,
                         total_likes=total_likes,
                         total_comments=total_comments,
                         recent_users=recent_users,
                         recent_posts=recent_posts)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot delete admin users.', 'danger')
        return redirect(url_for('admin_users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/posts')
@login_required
@admin_required
def admin_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('admin/posts.html', posts=posts)

@app.route('/admin/post/<int:post_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted successfully.', 'success')
    return redirect(url_for('admin_posts'))

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Admin status updated for {user.username}.', 'success')
    return redirect(url_for('admin_users'))

# Initialize database
with app.app_context():
    db.create_all()
    # Create default admin if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', email='admin@twitter.com', is_admin=True)
        admin.set_password('Admin321')
        db.session.add(admin)
        db.session.commit()

@app.template_filter('process_content')
def process_content_filter(content):
    return process_content(content)

@app.template_filter('time_ago')
def time_ago_filter(dt):
    now = datetime.utcnow()
    diff = now - dt
    
    if diff.days > 365:
        years = diff.days // 365
        return f'{years} year{"s" if years > 1 else ""} ago'
    elif diff.days > 30:
        months = diff.days // 30
        return f'{months} month{"s" if months > 1 else ""} ago'
    elif diff.days > 0:
        return f'{diff.days} day{"s" if diff.days > 1 else ""} ago'
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f'{hours} hour{"s" if hours > 1 else ""} ago'
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f'{minutes} minute{"s" if minutes > 1 else ""} ago'
    else:
        return 'Just now'

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)