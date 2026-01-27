from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import os
import secrets
import re
from sqlalchemy import or_, func, desc, and_
from sqlalchemy.orm import joinedload

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///twitter_clone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# Create upload directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'posts'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'covers'), exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Association table for followers
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

# Association table for blocking users
blocked_users = db.Table('blocked_users',
    db.Column('blocker_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('blocked_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('blocked_at', db.DateTime, default=datetime.utcnow)
)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    bio = db.Column(db.String(500))
    location = db.Column(db.String(100))
    website = db.Column(db.String(200))
    profile_picture = db.Column(db.String(200), default='default.jpg')
    cover_picture = db.Column(db.String(200), default='default_cover.jpg')
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
    
    # Relationships
    posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')
    bookmarks = db.relationship('Bookmark', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    reports_made = db.relationship('Report', foreign_keys='Report.reporter_id', backref='reporter', lazy='dynamic')
    reports_received = db.relationship('Report', foreign_keys='Report.reported_id', backref='reported', lazy='dynamic')
    pinned_posts = db.relationship('PinnedPost', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    created_lists = db.relationship('UserList', backref='creator', lazy='dynamic', cascade='all, delete-orphan')
    list_subscriptions = db.relationship('ListSubscriber', backref='subscriber', lazy='dynamic', cascade='all, delete-orphan')
    list_memberships = db.relationship('ListMember', backref='member', lazy='dynamic', cascade='all, delete-orphan')
    
    # Many-to-many relationships
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
    
    blocked = db.relationship(
        'User', secondary=blocked_users,
        primaryjoin=(blocked_users.c.blocker_id == id),
        secondaryjoin=(blocked_users.c.blocked_id == id),
        backref=db.backref('blocked_by', lazy='dynamic'), lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def follow(self, user):
        if not self.is_following(user) and not self.has_blocked(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

    def block(self, user):
        if not self.has_blocked(user):
            # Unfollow each other if following
            if self.is_following(user):
                self.unfollow(user)
            if user.is_following(self):
                user.unfollow(self)
            
            self.blocked.append(user)

    def unblock(self, user):
        if self.has_blocked(user):
            self.blocked.remove(user)

    def has_blocked(self, user):
        return self.blocked.filter(blocked_users.c.blocked_id == user.id).count() > 0

    def is_blocked_by(self, user):
        return user.has_blocked(self)

    def can_interact_with(self, user):
        """Check if current user can interact with another user (not blocked)"""
        return not self.has_blocked(user) and not user.has_blocked(self)

    def get_unread_message_count(self):
        return Message.query.filter_by(receiver_id=self.id, is_read=False).count()

    def get_unread_notification_count(self):
        return Notification.query.filter_by(user_id=self.id, is_read=False).count()

    def get_accessible_lists(self):
        """Get all lists the user can view (public or their own or subscribed)"""
        # Lists created by user
        created = db.session.query(UserList.id).filter(UserList.user_id == self.id)
        
        # Lists user is subscribed to
        subscribed = db.session.query(ListSubscriber.list_id).filter(ListSubscriber.user_id == self.id)
        
        # Public lists
        public = db.session.query(UserList.id).filter(UserList.is_private == False)
        
        # Combine
        accessible_ids = created.union(subscribed).union(public)
        
        return UserList.query.filter(UserList.id.in_(accessible_ids)).distinct()

    def get_mutual_followers(self, user):
        """Get mutual followers between two users"""
        return self.followers.filter(User.followed.contains(user)).all()

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)
    
    # Relationships
    likes = db.relationship('Like', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    hashtags = db.relationship('PostHashtag', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    bookmarks = db.relationship('Bookmark', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='post', lazy='dynamic', cascade='all, delete-orphan')
    pin_relation = db.relationship('PinnedPost', backref='post', uselist=False, cascade='all, delete-orphan')

    def like_count(self):
        return self.likes.count()

    def comment_count(self):
        return self.comments.count()

    def bookmark_count(self):
        return self.bookmarks.count()

    def is_pinned_by(self, user):
        """Check if this post is pinned by a specific user"""
        return PinnedPost.query.filter_by(user_id=user.id, post_id=self.id).first() is not None

    def can_view(self, user):
        """Check if a user can view this post"""
        if self.is_deleted:
            return False
        
        author = User.query.get(self.user_id)
        if not author or not user:
            return False
        
        # Check if either user has blocked the other
        if author.has_blocked(user) or user.has_blocked(author):
            return False
        
        return True

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_like'),)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    link = db.Column(db.String(200))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    notification_type = db.Column(db.String(50))  # like, comment, follow, mention, message

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class Hashtag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(100), unique=True, nullable=False)
    count = db.Column(db.Integer, default=1)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)

class PostHashtag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    hashtag_id = db.Column(db.Integer, db.ForeignKey('hashtag.id'), nullable=False)

class Bookmark(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', 'post_id', name='unique_bookmark'),)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reported_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))
    reason = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(50), default='pending')  # pending, reviewed, resolved, dismissed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'))

# New models for Pins and Lists
class PinnedPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    pinned_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('user_id', name='one_pin_per_user'),)

class UserList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    members = db.relationship('ListMember', backref='list', lazy='dynamic', cascade='all, delete-orphan')
    subscribers = db.relationship('ListSubscriber', backref='list', lazy='dynamic', cascade='all, delete-orphan')

class ListMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey('user_list.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('list_id', 'user_id', name='unique_list_member'),)

class ListSubscriber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey('user_list.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subscribed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('list_id', 'user_id', name='unique_list_subscriber'),)

# Helper functions
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
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'mov', 'avi'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_hashtags(content):
    return re.findall(r'#(\w+)', content)

def extract_mentions(content):
    return re.findall(r'@(\w+)', content)

def process_content(content):
    if not content:
        return ''
    content = re.sub(r'#(\w+)', r'<a href="/hashtag/\1" class="text-primary hashtag">#\1</a>', content)
    content = re.sub(r'@(\w+)', r'<a href="/profile/\1" class="text-info mention">@\1</a>', content)
    return content

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return "Password must contain at least one number"
    return None

def validate_username(username):
    """Validate username"""
    if len(username) < 3 or len(username) > 30:
        return "Username must be between 3 and 30 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return "Username can only contain letters, numbers, and underscores"
    return None

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        # Auto-mark as offline if last seen > 5 minutes ago
        if current_user.is_online and (datetime.utcnow() - current_user.last_seen).seconds > 300:
            current_user.is_online = False
        db.session.commit()

@app.before_request
def check_blocked():
    if current_user.is_authenticated:
        # Check if viewing a blocked user's content
        pass

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
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # Validation
        username_error = validate_username(username)
        if username_error:
            flash(username_error, 'danger')
            return redirect(url_for('signup'))
        
        password_error = validate_password(password)
        if password_error:
            flash(password_error, 'danger')
            return redirect(url_for('signup'))
        
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email address.', 'danger')
            return redirect(url_for('signup'))
        
        # Check for existing user
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('signup'))
        
        # Create user
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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            user.is_online = True
            db.session.commit()
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('feed'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    current_user.is_online = False
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

@app.route('/feed')
@login_required
def feed():
    page = request.args.get('page', 1, type=int)
    
    # Get users that current user follows
    followed_users = current_user.followed.all()
    followed_ids = [u.id for u in followed_users] + [current_user.id]
    
    # Exclude blocked users
    blocked_users = [b.id for b in current_user.blocked.all()]
    blocked_by = [b.id for b in current_user.blocked_by.all()]
    
    # Get posts from followed users, excluding blocked content
    posts_query = Post.query.filter(
        Post.user_id.in_(followed_ids),
        Post.is_deleted == False,
        ~Post.user_id.in_(blocked_users),
        ~Post.user_id.in_(blocked_by)
    ).order_by(Post.created_at.desc())
    
    posts = posts_query.paginate(page=page, per_page=20, error_out=False)
    
    # Get trending hashtags
    trending = Hashtag.query.order_by(Hashtag.count.desc(), Hashtag.last_used.desc()).limit(5).all()
    
    # Get user suggestions (not followed, not blocked)
    suggestions = User.query.filter(
        User.id != current_user.id,
        ~User.id.in_(followed_ids),
        ~User.id.in_(blocked_users),
        ~User.id.in_(blocked_by)
    ).order_by(func.random()).limit(5).all()
    
    return render_template('feed.html', posts=posts, trending=trending, suggestions=suggestions)

@app.route('/post', methods=['POST'])
@login_required
def create_post():
    content = request.form.get('content', '').strip()
    image = request.files.get('image')
    
    if not content and not image:
        flash('Post cannot be empty.', 'danger')
        return redirect(url_for('feed'))
    
    if len(content) > 280:
        flash('Post cannot exceed 280 characters.', 'danger')
        return redirect(url_for('feed'))
    
    post = Post(content=content, user_id=current_user.id)
    
    if image and allowed_file(image.filename):
        filename = secure_filename(f"{secrets.token_hex(8)}_{image.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'posts', filename)
        image.save(filepath)
        post.image = filename
    
    db.session.add(post)
    db.session.flush()
    
    # Process hashtags
    hashtags = extract_hashtags(content)
    for tag in hashtags[:10]:  # Limit to 10 hashtags per post
        existing = Hashtag.query.filter_by(tag=tag).first()
        if existing:
            existing.count += 1
            existing.last_used = datetime.utcnow()
        else:
            existing = Hashtag(tag=tag)
            db.session.add(existing)
            db.session.flush()
        
        post_hashtag = PostHashtag(post_id=post.id, hashtag_id=existing.id)
        db.session.add(post_hashtag)
    
    # Process mentions
    mentions = extract_mentions(content)
    for username in mentions:
        mentioned_user = User.query.filter_by(username=username).first()
        if mentioned_user and mentioned_user.id != current_user.id and current_user.can_interact_with(mentioned_user):
            notif = Notification(
                user_id=mentioned_user.id,
                content=f"{current_user.username} mentioned you in a post",
                link=f"/post/{post.id}",
                notification_type='mention'
            )
            db.session.add(notif)
    
    db.session.commit()
    flash('Post created successfully!', 'success')
    return redirect(url_for('feed'))

@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    if not post.can_view(current_user):
        flash('You cannot view this post.', 'danger')
        return redirect(url_for('feed'))
    
    comments = Comment.query.filter_by(
        post_id=post_id, 
        is_deleted=False
    ).order_by(Comment.created_at.desc()).all()
    
    # Check if bookmarked
    is_bookmarked = Bookmark.query.filter_by(
        user_id=current_user.id,
        post_id=post_id
    ).first() is not None
    
    return render_template('post.html', post=post, comments=comments, is_bookmarked=is_bookmarked)

@app.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    if post.user_id != current_user.id and not current_user.is_admin:
        flash('You can only delete your own posts.', 'danger')
        return redirect(url_for('view_post', post_id=post_id))
    
    post.is_deleted = True
    post.deleted_at = datetime.utcnow()
    db.session.commit()
    
    flash('Post deleted successfully.', 'success')
    return redirect(url_for('profile', username=current_user.username))

@app.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    if post.user_id != current_user.id:
        flash('You can only edit your own posts.', 'danger')
        return redirect(url_for('view_post', post_id=post_id))
    
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        
        if len(content) > 280:
            flash('Post cannot exceed 280 characters.', 'danger')
            return redirect(url_for('edit_post', post_id=post_id))
        
        post.content = content
        post.created_at = datetime.utcnow()  # Update timestamp for sorting
        
        # Remove existing hashtags
        PostHashtag.query.filter_by(post_id=post.id).delete()
        
        # Add new hashtags
        hashtags = extract_hashtags(content)
        for tag in hashtags[:10]:
            existing = Hashtag.query.filter_by(tag=tag).first()
            if existing:
                existing.count += 1
                existing.last_used = datetime.utcnow()
            else:
                existing = Hashtag(tag=tag)
                db.session.add(existing)
                db.session.flush()
            
            post_hashtag = PostHashtag(post_id=post.id, hashtag_id=existing.id)
            db.session.add(post_hashtag)
        
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('view_post', post_id=post_id))
    
    return render_template('edit_post.html', post=post)

@app.route('/post/<int:post_id>/like', methods=['POST'])
@login_required
def like_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        
        if not post.can_view(current_user):
            return jsonify({'error': 'You cannot interact with this post.'}), 403
        
        existing_like = Like.query.filter_by(
            user_id=current_user.id, 
            post_id=post_id
        ).first()
        
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
                    link=f"/post/{post_id}",
                    notification_type='like'
                )
                db.session.add(notif)
            liked = True
        
        db.session.commit()
        
        return jsonify({
            'status': 'liked' if liked else 'unliked', 
            'count': post.like_count()
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/post/<int:post_id>/bookmark', methods=['POST'])
@login_required
def bookmark_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        
        if not post.can_view(current_user):
            return jsonify({'error': 'You cannot bookmark this post.'}), 403
        
        existing_bookmark = Bookmark.query.filter_by(
            user_id=current_user.id,
            post_id=post_id
        ).first()
        
        if existing_bookmark:
            db.session.delete(existing_bookmark)
            bookmarked = False
        else:
            bookmark = Bookmark(user_id=current_user.id, post_id=post_id)
            db.session.add(bookmark)
            bookmarked = True
        
        db.session.commit()
        
        return jsonify({
            'status': 'bookmarked' if bookmarked else 'unbookmarked',
            'count': post.bookmark_count()
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/bookmarks')
@login_required
def bookmarks():
    page = request.args.get('page', 1, type=int)
    
    bookmarks_query = Bookmark.query.filter_by(
        user_id=current_user.id
    ).join(Post).filter(
        Post.is_deleted == False,
        ~Post.user_id.in_([b.id for b in current_user.blocked.all()]),
        ~Post.user_id.in_([b.id for b in current_user.blocked_by.all()])
    ).order_by(Bookmark.created_at.desc())
    
    bookmarks_paginated = bookmarks_query.paginate(page=page, per_page=20, error_out=False)
    
    posts = [bookmark.post for bookmark in bookmarks_paginated.items]
    
    return render_template('bookmarks.html', posts=posts, pagination=bookmarks_paginated)

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@login_required
def comment_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    if not post.can_view(current_user):
        flash('You cannot comment on this post.', 'danger')
        return redirect(url_for('view_post', post_id=post_id))
    
    content = request.form.get('content', '').strip()
    
    if not content:
        flash('Comment cannot be empty.', 'danger')
        return redirect(url_for('view_post', post_id=post_id))
    
    if len(content) > 280:
        flash('Comment cannot exceed 280 characters.', 'danger')
        return redirect(url_for('view_post', post_id=post_id))
    
    comment = Comment(
        content=content, 
        user_id=current_user.id, 
        post_id=post_id
    )
    db.session.add(comment)
    
    if post.author.id != current_user.id:
        notif = Notification(
            user_id=post.author.id,
            content=f"{current_user.username} commented on your post",
            link=f"/post/{post_id}",
            notification_type='comment'
        )
        db.session.add(notif)
    
    # Process mentions in comment
    mentions = extract_mentions(content)
    for username in mentions:
        mentioned_user = User.query.filter_by(username=username).first()
        if (mentioned_user and mentioned_user.id != current_user.id and 
            mentioned_user.id != post.author.id and 
            current_user.can_interact_with(mentioned_user)):
            notif = Notification(
                user_id=mentioned_user.id,
                content=f"{current_user.username} mentioned you in a comment",
                link=f"/post/{post_id}",
                notification_type='mention'
            )
            db.session.add(notif)
    
    db.session.commit()
    flash('Comment added!', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    post_id = comment.post_id
    
    if comment.user_id != current_user.id and not current_user.is_admin:
        flash('You can only delete your own comments.', 'danger')
        return redirect(url_for('view_post', post_id=post_id))
    
    comment.is_deleted = True
    comment.deleted_at = datetime.utcnow()
    db.session.commit()
    
    flash('Comment deleted.', 'success')
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    
    # Check if blocked
    if current_user.has_blocked(user) or user.has_blocked(current_user):
        flash('This profile is not available.', 'danger')
        return redirect(url_for('feed'))
    
    # Get posts (excluding deleted ones)
    posts = Post.query.filter_by(
        user_id=user.id, 
        is_deleted=False
    ).order_by(Post.created_at.desc()).all()
    
    # Get pinned post
    pinned_post_data = PinnedPost.query.filter_by(user_id=user.id).first()
    pinned_post = pinned_post_data.post if pinned_post_data and not pinned_post_data.post.is_deleted else None
    
    # Calculate stats
    total_likes = sum(post.like_count() for post in posts)
    total_posts = len(posts)
    total_followers = user.followers.count()
    total_following = user.followed.count()
    
    # Check relationships
    is_following = current_user.is_following(user)
    is_blocked = current_user.has_blocked(user)
    is_blocked_by = user.has_blocked(current_user)
    
    # Get mutual followers
    mutual_followers = current_user.get_mutual_followers(user) if current_user.is_authenticated else []
    
    return render_template('profile.html', 
                         user=user, 
                         posts=posts, 
                         pinned_post=pinned_post,
                         total_likes=total_likes,
                         total_posts=total_posts,
                         total_followers=total_followers,
                         total_following=total_following,
                         is_following=is_following,
                         is_blocked=is_blocked,
                         is_blocked_by=is_blocked_by,
                         mutual_followers=mutual_followers[:5])

@app.route('/profile/<username>/followers')
@login_required
def profile_followers(username):
    user = User.query.filter_by(username=username).first_or_404()
    
    if not current_user.can_interact_with(user):
        flash('You cannot view this profile.', 'danger')
        return redirect(url_for('feed'))
    
    followers_list = user.followers.all()
    
    return render_template('profile_followers.html', 
                         user=user, 
                         followers=followers_list)

@app.route('/profile/<username>/following')
@login_required
def profile_following(username):
    user = User.query.filter_by(username=username).first_or_404()
    
    if not current_user.can_interact_with(user):
        flash('You cannot view this profile.', 'danger')
        return redirect(url_for('feed'))
    
    following_list = user.followed.all()
    
    return render_template('profile_following.html', 
                         user=user, 
                         following=following_list)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.bio = request.form.get('bio', '').strip()
        current_user.location = request.form.get('location', '').strip()
        current_user.website = request.form.get('website', '').strip()
        
        # Profile picture
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{current_user.id}_profile_{secrets.token_hex(8)}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', filename))
                current_user.profile_picture = filename
        
        # Cover picture
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

@app.route('/profile/<username>/pinned')
@login_required
def pinned_posts(username):
    user = User.query.filter_by(username=username).first_or_404()
    
    if not current_user.can_interact_with(user):
        flash('You cannot view this profile.', 'danger')
        return redirect(url_for('feed'))
    
    # Get all pinned posts for this user
    pinned_posts_data = PinnedPost.query.filter_by(user_id=user.id).order_by(
        PinnedPost.pinned_at.desc()
    ).all()
    
    pinned_posts = [pinned.post for pinned in pinned_posts_data if not pinned.post.is_deleted]
    
    return render_template('pinned_posts.html', 
                         user=user, 
                         posts=pinned_posts,
                         title=f"{user.username}'s Pinned Posts")

@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        if user.id == current_user.id:
            return jsonify({'error': 'Cannot follow yourself'}), 400
        
        if not current_user.can_interact_with(user):
            return jsonify({'error': 'Cannot follow this user'}), 403
        
        if current_user.is_following(user):
            current_user.unfollow(user)
            status = 'unfollowed'
            message = f'Unfollowed {user.username}'
        else:
            current_user.follow(user)
            
            notif = Notification(
                user_id=user.id,
                content=f"{current_user.username} started following you",
                link=f"/profile/{current_user.username}",
                notification_type='follow'
            )
            db.session.add(notif)
            status = 'followed'
            message = f'Started following {user.username}'
        
        db.session.commit()
        return jsonify({
            'status': status,
            'message': message,
            'follower_count': user.followers.count()
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/block/<int:user_id>', methods=['POST'])
@login_required
def block_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        if user.id == current_user.id:
            return jsonify({'error': 'Cannot block yourself'}), 400
        
        if current_user.has_blocked(user):
            current_user.unblock(user)
            status = 'unblocked'
            message = f'Unblocked {user.username}'
        else:
            current_user.block(user)
            status = 'blocked'
            message = f'Blocked {user.username}'
        
        db.session.commit()
        return jsonify({'status': status, 'message': message})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/report', methods=['POST'])
@login_required
def report_content():
    try:
        reported_id = request.form.get('reported_id', type=int)
        post_id = request.form.get('post_id', type=int)
        reason = request.form.get('reason', '').strip()
        
        if not reason:
            return jsonify({'error': 'Please provide a reason for reporting.'}), 400
        
        reported_user = User.query.get(reported_id)
        if not reported_user:
            return jsonify({'error': 'User not found.'}), 404
        
        if reported_id == current_user.id:
            return jsonify({'error': 'Cannot report yourself.'}), 400
        
        # Check if already reported
        existing_report = Report.query.filter_by(
            reporter_id=current_user.id,
            reported_id=reported_id,
            post_id=post_id if post_id else None
        ).first()
        
        if existing_report:
            return jsonify({'error': 'You have already reported this content.'}), 400
        
        report = Report(
            reporter_id=current_user.id,
            reported_id=reported_id,
            post_id=post_id,
            reason=reason
        )
        
        db.session.add(report)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Report submitted successfully.'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    search_type = request.args.get('type', 'all')  # all, users, posts, lists
    
    if not query:
        return render_template('search.html', query=query, users=[], posts=[], lists=[])
    
    # Filter out blocked users
    blocked_ids = [b.id for b in current_user.blocked.all()]
    blocked_by_ids = [b.id for b in current_user.blocked_by.all()]
    
    results = {
        'users': [],
        'posts': [],
        'lists': []
    }
    
    if search_type in ['all', 'users']:
        users = User.query.filter(
            or_(
                User.username.contains(query),
                User.bio.contains(query)
            ),
            User.id != current_user.id,
            ~User.id.in_(blocked_ids),
            ~User.id.in_(blocked_by_ids)
        ).limit(20).all()
        results['users'] = users
    
    if search_type in ['all', 'posts']:
        if query.startswith('#'):
            tag = query[1:]
            hashtag = Hashtag.query.filter_by(tag=tag).first()
            if hashtag:
                posts_with_tag = Post.query.join(PostHashtag).filter(
                    PostHashtag.hashtag_id == hashtag.id,
                    Post.is_deleted == False,
                    ~Post.user_id.in_(blocked_ids),
                    ~Post.user_id.in_(blocked_by_ids)
                ).order_by(Post.created_at.desc()).limit(20).all()
                results['posts'] = posts_with_tag
        else:
            posts = Post.query.filter(
                Post.content.contains(query),
                Post.is_deleted == False,
                ~Post.user_id.in_(blocked_ids),
                ~Post.user_id.in_(blocked_by_ids)
            ).order_by(Post.created_at.desc()).limit(20).all()
            results['posts'] = posts
    
    if search_type in ['all', 'lists']:
        lists = UserList.query.filter(
            or_(
                UserList.name.contains(query),
                UserList.description.contains(query)
            ),
            or_(
                UserList.user_id == current_user.id,
                and_(UserList.is_private == False, UserList.user_id.notin_(blocked_ids))
            )
        ).limit(10).all()
        results['lists'] = lists
    
    return render_template('search.html', 
                         query=query, 
                         search_type=search_type,
                         **results)

@app.route('/hashtag/<tag>')
@login_required
def hashtag(tag):
    hashtag_obj = Hashtag.query.filter_by(tag=tag).first()
    
    if not hashtag_obj:
        flash('No posts found with this hashtag.', 'info')
        return redirect(url_for('feed'))
    
    page = request.args.get('page', 1, type=int)
    
    # Filter out blocked content
    blocked_ids = [b.id for b in current_user.blocked.all()]
    blocked_by_ids = [b.id for b in current_user.blocked_by.all()]
    
    posts_query = Post.query.join(PostHashtag).filter(
        PostHashtag.hashtag_id == hashtag_obj.id,
        Post.is_deleted == False,
        ~Post.user_id.in_(blocked_ids),
        ~Post.user_id.in_(blocked_by_ids)
    ).order_by(Post.created_at.desc())
    
    posts = posts_query.paginate(page=page, per_page=20, error_out=False)
    
    return render_template('hashtag.html', 
                         tag=tag, 
                         posts=posts, 
                         hashtag=hashtag_obj)

@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    
    notifs_query = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc())
    
    notifs = notifs_query.paginate(page=page, per_page=20, error_out=False)
    
    # Mark as read
    for notif in notifs.items:
        if not notif.is_read:
            notif.is_read = True
    
    db.session.commit()
    
    return render_template('notifications.html', notifications=notifs)

@app.route('/notifications/clear', methods=['POST'])
@login_required
def clear_notifications():
    Notification.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('All notifications cleared.', 'success')
    return redirect(url_for('notifications'))

@app.route('/notifications/read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notif = Notification.query.get_or_404(notification_id)
    
    if notif.user_id != current_user.id:
        abort(403)
    
    notif.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/messages')
@login_required
def messages():
    # Get conversations with users that aren't blocked
    blocked_ids = [b.id for b in current_user.blocked.all()]
    
    # Get all unique conversation partners
    sent_to = db.session.query(Message.receiver_id).filter(
        Message.sender_id == current_user.id,
        ~Message.receiver_id.in_(blocked_ids)
    ).distinct()
    
    received_from = db.session.query(Message.sender_id).filter(
        Message.receiver_id == current_user.id,
        ~Message.sender_id.in_(blocked_ids)
    ).distinct()
    
    conversation_ids = set([id[0] for id in sent_to] + [id[0] for id in received_from])
    
    conversations = []
    for user_id in conversation_ids:
        if user_id == current_user.id:
            continue
            
        user = User.query.get(user_id)
        if not user:
            continue
        
        # Get last message
        last_message = Message.query.filter(
            or_(
                (Message.sender_id == current_user.id) & (Message.receiver_id == user_id),
                (Message.sender_id == user_id) & (Message.receiver_id == current_user.id)
            )
        ).order_by(Message.created_at.desc()).first()
        
        if not last_message:
            continue
        
        # Get unread count
        unread_count = Message.query.filter_by(
            sender_id=user_id,
            receiver_id=current_user.id,
            is_read=False
        ).count()
        
        conversations.append({
            'user': user,
            'last_message': last_message,
            'unread_count': unread_count,
            'last_active': max(user.last_seen, last_message.created_at)
        })
    
    # Sort by last message time
    conversations.sort(key=lambda x: x['last_message'].created_at, reverse=True)
    
    return render_template('messages.html', conversations=conversations)

@app.route('/messages/<int:user_id>', methods=['GET', 'POST'])
@login_required
def conversation(user_id):
    user = User.query.get_or_404(user_id)
    
    # Check if blocked
    if not current_user.can_interact_with(user):
        flash('You cannot message this user.', 'danger')
        return redirect(url_for('messages'))
    
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        
        if not content:
            flash('Message cannot be empty.', 'danger')
            return redirect(url_for('conversation', user_id=user_id))
        
        if len(content) > 1000:
            flash('Message is too long.', 'danger')
            return redirect(url_for('conversation', user_id=user_id))
        
        message = Message(
            sender_id=current_user.id,
            receiver_id=user.id,
            content=content
        )
        db.session.add(message)
        
        # Create notification
        notif = Notification(
            user_id=user.id,
            content=f"{current_user.username} sent you a message",
            link=f"/messages/{current_user.id}",
            notification_type='message'
        )
        db.session.add(notif)
        
        db.session.commit()
        
        return redirect(url_for('conversation', user_id=user_id))
    
    # Get messages
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
    
    if not current_user.can_interact_with(user):
        return jsonify({'error': 'Cannot access messages with this user.'}), 403
    
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
            'content': process_content(msg.content),
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
        content = data.get('content', '').strip()
        
        if not content or not receiver_id:
            return jsonify({'error': 'Message content and receiver are required'}), 400
        
        if len(content) > 1000:
            return jsonify({'error': 'Message is too long'}), 400
        
        receiver = User.query.get(receiver_id)
        if not receiver:
            return jsonify({'error': 'User not found'}), 404
        
        if not current_user.can_interact_with(receiver):
            return jsonify({'error': 'Cannot message this user'}), 403
        
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            content=content
        )
        
        db.session.add(message)
        
        # Create notification
        notif = Notification(
            user_id=receiver_id,
            content=f"{current_user.username} sent you a message",
            link=f"/messages/{current_user.id}",
            notification_type='message'
        )
        db.session.add(notif)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': {
                'id': message.id,
                'sender_id': message.sender_id,
                'receiver_id': message.receiver_id,
                'content': process_content(message.content),
                'is_read': message.is_read,
                'created_at': message.created_at.isoformat(),
                'sender_username': current_user.username,
                'sender_profile_picture': current_user.profile_picture
            }
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/messages/search')
@login_required
def message_search():
    query = request.args.get('q', '').strip()
    
    if not query:
        return jsonify({'users': []})
    
    # Filter out blocked users
    blocked_ids = [b.id for b in current_user.blocked.all()]
    blocked_by_ids = [b.id for b in current_user.blocked_by.all()]
    
    users = User.query.filter(
        User.username.contains(query),
        User.id != current_user.id,
        ~User.id.in_(blocked_ids),
        ~User.id.in_(blocked_by_ids)
    ).limit(10).all()
    
    return jsonify({
        'users': [{
            'id': user.id,
            'username': user.username,
            'profile_picture': user.profile_picture,
            'is_online': user.is_online,
            'last_seen': user.last_seen.isoformat() if user.last_seen else None
        } for user in users]
    })

@app.route('/trending')
@login_required
def trending():
    # Get trending hashtags (most used in last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    
    trending_hashtags = Hashtag.query.filter(
        Hashtag.last_used >= week_ago
    ).order_by(Hashtag.count.desc()).limit(20).all()
    
    # Get trending posts (most liked in last 24 hours)
    yesterday = datetime.utcnow() - timedelta(days=1)
    
    trending_posts = db.session.query(Post).join(Like).filter(
        Post.created_at >= yesterday,
        Post.is_deleted == False
    ).group_by(Post.id).order_by(func.count(Like.id).desc()).limit(20).all()
    
    # Get popular users (most followers gained in last week)
    # This is a simplified version - in production you'd track follower changes
    popular_users = User.query.order_by(
        func.random()  # Simplified - would use follower growth metric
    ).limit(10).all()
    
    return render_template('trending.html', 
                         hashtags=trending_hashtags, 
                         posts=trending_posts,
                         users=popular_users)

# Lists Routes
@app.route('/lists')
@login_required
def lists():
    """Show all lists accessible to the user"""
    created_lists = UserList.query.filter_by(user_id=current_user.id).all()
    
    subscribed_lists = UserList.query.join(ListSubscriber).filter(
        ListSubscriber.user_id == current_user.id,
        UserList.user_id != current_user.id
    ).all()
    
    public_lists = UserList.query.filter_by(is_private=False).filter(
        UserList.user_id != current_user.id,
        ~UserList.id.in_([l.id for l in subscribed_lists])
    ).order_by(func.random()).limit(10).all()
    
    return render_template('lists/lists.html',
                         created_lists=created_lists,
                         subscribed_lists=subscribed_lists,
                         public_lists=public_lists)

@app.route('/lists/create', methods=['GET', 'POST'])
@login_required
def create_list():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        is_private = request.form.get('is_private') == 'on'
        
        if not name:
            flash('List name is required', 'danger')
            return redirect(url_for('create_list'))
        
        if len(name) > 100:
            flash('List name cannot exceed 100 characters', 'danger')
            return redirect(url_for('create_list'))
        
        # Check if list name already exists for this user
        existing = UserList.query.filter_by(
            name=name, 
            user_id=current_user.id
        ).first()
        
        if existing:
            flash('You already have a list with this name', 'danger')
            return redirect(url_for('create_list'))
        
        # Create new list
        new_list = UserList(
            name=name,
            description=description,
            user_id=current_user.id,
            is_private=is_private
        )
        
        db.session.add(new_list)
        db.session.commit()
        
        flash('List created successfully!', 'success')
        return redirect(url_for('view_list', list_id=new_list.id))
    
    return render_template('lists/create_list.html')

@app.route('/lists/<int:list_id>')
@login_required
def view_list(list_id):
    user_list = UserList.query.get_or_404(list_id)
    
    # Check access
    if user_list.is_private and user_list.user_id != current_user.id:
        # Check if user is subscribed
        subscription = ListSubscriber.query.filter_by(
            list_id=list_id,
            user_id=current_user.id
        ).first()
        
        if not subscription:
            flash('This list is private', 'danger')
            return redirect(url_for('lists'))
    
    # Get list members
    members = User.query.join(ListMember).filter(
        ListMember.list_id == list_id
    ).order_by(User.username).all()
    
    # Get list subscribers count
    subscriber_count = ListSubscriber.query.filter_by(list_id=list_id).count()
    
    # Check if current user is subscribed
    is_subscribed = ListSubscriber.query.filter_by(
        list_id=list_id,
        user_id=current_user.id
    ).first() is not None
    
    # Check if current user is a member
    is_member = ListMember.query.filter_by(
        list_id=list_id,
        user_id=current_user.id
    ).first() is not None
    
    return render_template('lists/view_list.html',
                         user_list=user_list,
                         members=members,
                         subscriber_count=subscriber_count,
                         is_subscribed=is_subscribed,
                         is_member=is_member,
                         is_owner=user_list.user_id == current_user.id)

@app.route('/lists/<int:list_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_list(list_id):
    user_list = UserList.query.get_or_404(list_id)
    
    # Check if user owns the list
    if user_list.user_id != current_user.id:
        flash('You can only edit your own lists', 'danger')
        return redirect(url_for('view_list', list_id=list_id))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        is_private = request.form.get('is_private') == 'on'
        
        if not name:
            flash('List name is required', 'danger')
            return redirect(url_for('edit_list', list_id=list_id))
        
        # Check if name already exists (excluding current list)
        existing = UserList.query.filter(
            UserList.name == name,
            UserList.user_id == current_user.id,
            UserList.id != list_id
        ).first()
        
        if existing:
            flash('You already have a list with this name', 'danger')
            return redirect(url_for('edit_list', list_id=list_id))
        
        user_list.name = name
        user_list.description = description
        user_list.is_private = is_private
        
        db.session.commit()
        flash('List updated successfully!', 'success')
        return redirect(url_for('view_list', list_id=list_id))
    
    return render_template('lists/edit_list.html', user_list=user_list)

@app.route('/lists/<int:list_id>/delete', methods=['POST'])
@login_required
def delete_list(list_id):
    user_list = UserList.query.get_or_404(list_id)
    
    # Check if user owns the list
    if user_list.user_id != current_user.id:
        flash('You can only delete your own lists', 'danger')
        return redirect(url_for('view_list', list_id=list_id))
    
    db.session.delete(user_list)
    db.session.commit()
    
    flash('List deleted successfully!', 'success')
    return redirect(url_for('lists'))

@app.route('/lists/<int:list_id>/add_member', methods=['POST'])
@login_required
def add_list_member(list_id):
    user_list = UserList.query.get_or_404(list_id)
    
    # Check if user owns the list
    if user_list.user_id != current_user.id:
        return jsonify({'error': 'You can only add members to your own lists'}), 403
    
    username = request.form.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    
    user_to_add = User.query.filter_by(username=username).first()
    if not user_to_add:
        return jsonify({'error': 'User not found'}), 404
    
    # Check if user is already in the list
    existing_member = ListMember.query.filter_by(
        list_id=list_id,
        user_id=user_to_add.id
    ).first()
    
    if existing_member:
        return jsonify({'error': 'User is already in the list'}), 400
    
    # Add user to list
    list_member = ListMember(list_id=list_id, user_id=user_to_add.id)
    db.session.add(list_member)
    
    # Create notification for the added user
    notif = Notification(
        user_id=user_to_add.id,
        content=f"{current_user.username} added you to list '{user_list.name}'",
        link=f"/lists/{list_id}",
        notification_type='list'
    )
    db.session.add(notif)
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'member': {
            'id': user_to_add.id,
            'username': user_to_add.username,
            'profile_picture': user_to_add.profile_picture
        }
    })

@app.route('/lists/<int:list_id>/remove_member/<int:user_id>', methods=['POST'])
@login_required
def remove_list_member(list_id, user_id):
    user_list = UserList.query.get_or_404(list_id)
    
    # Check if user owns the list
    if user_list.user_id != current_user.id:
        return jsonify({'error': 'You can only remove members from your own lists'}), 403
    
    # Find and remove the member
    list_member = ListMember.query.filter_by(
        list_id=list_id,
        user_id=user_id
    ).first()
    
    if not list_member:
        return jsonify({'error': 'User is not in the list'}), 404
    
    db.session.delete(list_member)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/lists/<int:list_id>/subscribe', methods=['POST'])
@login_required
def subscribe_to_list(list_id):
    user_list = UserList.query.get_or_404(list_id)
    
    # Check if user can subscribe (not private or is owner)
    if user_list.is_private and user_list.user_id != current_user.id:
        return jsonify({'error': 'This list is private'}), 403
    
    # Check if already subscribed
    existing = ListSubscriber.query.filter_by(
        list_id=list_id,
        user_id=current_user.id
    ).first()
    
    if existing:
        # Unsubscribe
        db.session.delete(existing)
        status = 'unsubscribed'
        message = f'Unsubscribed from {user_list.name}'
    else:
        # Subscribe
        subscription = ListSubscriber(list_id=list_id, user_id=current_user.id)
        db.session.add(subscription)
        status = 'subscribed'
        message = f'Subscribed to {user_list.name}'
    
    db.session.commit()
    return jsonify({'status': status, 'message': message})

@app.route('/lists/feed/<int:list_id>')
@login_required
def list_feed(list_id):
    """Show feed of posts from list members"""
    user_list = UserList.query.get_or_404(list_id)
    
    # Check access
    if user_list.is_private and user_list.user_id != current_user.id:
        subscription = ListSubscriber.query.filter_by(
            list_id=list_id,
            user_id=current_user.id
        ).first()
        
        if not subscription:
            flash('This list is private', 'danger')
            return redirect(url_for('lists'))
    
    # Get list members
    members = User.query.join(ListMember).filter(
        ListMember.list_id == list_id
    ).all()
    
    member_ids = [member.id for member in members]
    
    page = request.args.get('page', 1, type=int)
    posts = Post.query.filter(
        Post.user_id.in_(member_ids),
        Post.is_deleted == False
    ).order_by(Post.created_at.desc()).paginate(page=page, per_page=20, error_out=False)
    
    return render_template('lists/list_feed.html',
                         user_list=user_list,
                         posts=posts)

@app.route('/api/lists/search_users')
@login_required
def search_list_users():
    """Search users to add to a list"""
    query = request.args.get('q', '').strip()
    list_id = request.args.get('list_id', type=int)
    
    if not query or not list_id:
        return jsonify({'users': []})
    
    # Get users already in the list
    existing_members = db.session.query(ListMember.user_id).filter(
        ListMember.list_id == list_id
    )
    
    # Search users not already in the list
    users = User.query.filter(
        User.username.contains(query),
        User.id != current_user.id,
        ~User.id.in_(existing_members)
    ).limit(10).all()
    
    return jsonify({
        'users': [{
            'id': user.id,
            'username': user.username,
            'profile_picture': user.profile_picture,
            'bio': user.bio[:100] if user.bio else ''
        } for user in users]
    })

# Post Pinning Routes
@app.route('/post/<int:post_id>/pin', methods=['POST'])
@login_required
def pin_post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        
        # Check if user owns the post
        if post.user_id != current_user.id:
            return jsonify({'error': 'You can only pin your own posts'}), 403
        
        # Check if post is already pinned
        existing_pin = PinnedPost.query.filter_by(
            user_id=current_user.id, 
            post_id=post_id
        ).first()
        
        if existing_pin:
            # Unpin the post
            db.session.delete(existing_pin)
            status = 'unpinned'
            message = 'Post unpinned from profile'
        else:
            # Check if user already has a pinned post
            current_pin = PinnedPost.query.filter_by(user_id=current_user.id).first()
            if current_pin:
                # Remove existing pin
                db.session.delete(current_pin)
            
            # Create new pin
            pinned_post = PinnedPost(user_id=current_user.id, post_id=post_id)
            db.session.add(pinned_post)
            status = 'pinned'
            message = 'Post pinned to profile'
        
        db.session.commit()
        return jsonify({'status': status, 'message': message, 'post_id': post_id})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Admin Panel Routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_posts = Post.query.filter_by(is_deleted=False).count()
    total_likes = Like.query.count()
    total_comments = Comment.query.filter_by(is_deleted=False).count()
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_posts = Post.query.filter_by(is_deleted=False).order_by(Post.created_at.desc()).limit(10).all()
    
    # Get pending reports
    pending_reports = Report.query.filter_by(status='pending').count()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_posts=total_posts,
                         total_likes=total_likes,
                         total_comments=total_comments,
                         pending_reports=pending_reports,
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
    
    if user.id == current_user.id:
        flash('Cannot delete yourself.', 'danger')
        return redirect(url_for('admin_users'))
    
    if user.is_admin:
        flash('Cannot delete admin users.', 'danger')
        return redirect(url_for('admin_users'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Cannot change your own admin status.', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    flash(f'Admin status updated for {user.username}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/toggle_verify', methods=['POST'])
@login_required
@admin_required
def toggle_verify(user_id):
    user = User.query.get_or_404(user_id)
    
    user.is_verified = not user.is_verified
    db.session.commit()
    
    flash(f'Verification status updated for {user.username}.', 'success')
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
    
    post.is_deleted = True
    post.deleted_at = datetime.utcnow()
    
    db.session.commit()
    flash('Post deleted successfully.', 'success')
    return redirect(url_for('admin_posts'))

@app.route('/admin/post/<int:post_id>/restore', methods=['POST'])
@login_required
@admin_required
def admin_restore_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    post.is_deleted = False
    post.deleted_at = None
    
    db.session.commit()
    flash('Post restored successfully.', 'success')
    return redirect(url_for('admin_posts'))

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('admin/reports.html', reports=reports)

@app.route('/admin/report/<int:report_id>/resolve', methods=['POST'])
@login_required
@admin_required
def resolve_report(report_id):
    report = Report.query.get_or_404(report_id)
    
    report.status = 'resolved'
    report.reviewed_at = datetime.utcnow()
    report.reviewed_by = current_user.id
    
    db.session.commit()
    flash('Report marked as resolved.', 'success')
    return redirect(url_for('admin_reports'))

@app.route('/admin/report/<int:report_id>/dismiss', methods=['POST'])
@login_required
@admin_required
def dismiss_report(report_id):
    report = Report.query.get_or_404(report_id)
    
    report.status = 'dismissed'
    report.reviewed_at = datetime.utcnow()
    report.reviewed_by = current_user.id
    
    db.session.commit()
    flash('Report dismissed.', 'success')
    return redirect(url_for('admin_reports'))

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

# Template Filters
@app.template_filter('process_content')
def process_content_filter(content):
    return process_content(content)

@app.template_filter('time_ago')
def time_ago_filter(dt):
    now = datetime.utcnow()
    diff = now - dt
    
    if diff.days > 365:
        years = diff.days // 365
        return f'{years}y'
    elif diff.days > 30:
        months = diff.days // 30
        return f'{months}mo'
    elif diff.days > 0:
        return f'{diff.days}d'
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f'{hours}h'
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f'{minutes}m'
    else:
        return 'Just now'

@app.template_filter('format_datetime')
def format_datetime_filter(dt):
    return dt.strftime('%B %d, %Y at %I:%M %p')

@app.template_filter('truncate')
def truncate_filter(s, length=100):
    if len(s) <= length:
        return s
    return s[:length] + '...'

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create default admin if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(
            username='admin', 
            email='admin@twitterclone.com', 
            is_admin=True,
            is_verified=True
        )
        admin.set_password('Admin123!')
        db.session.add(admin)
        db.session.commit()
        print("Default admin created: username='admin', password='Admin123!'")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)