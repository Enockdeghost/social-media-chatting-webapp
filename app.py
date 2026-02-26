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
import qrcode
import hmac
import hashlib
from io import BytesIO
from flask import send_file
import qrcode.constants
import hmac
import hashlib
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
from flask import send_file

app = Flask(__name__)
DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///twitter_clone.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

app.config['SESSION_COOKIE_SECURE'] = not DEBUG     
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

app.config['REMEMBER_COOKIE_SECURE'] = not DEBUG
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)


os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'posts'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'covers'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'statuses'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'reels'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'post_thumbnails'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'reel_thumbnails'), exist_ok=True)

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

    # Reels & Status relationships
    reels = db.relationship('Reel', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    reel_likes = db.relationship('ReelLike', backref='liker', lazy='dynamic', cascade='all, delete-orphan')
    reel_comments = db.relationship('ReelComment', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    reel_views = db.relationship('ReelView', backref='viewer', lazy='dynamic', cascade='all, delete-orphan')
    statuses = db.relationship('Status', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    status_views = db.relationship('StatusView', backref='viewer', lazy='dynamic', cascade='all, delete-orphan')

    email_notifications = db.Column(db.Boolean, default=True)
    language = db.Column(db.String(10), default='en')
    theme = db.Column(db.String(20), default='dark')          
    autoplay_videos = db.Column(db.Boolean, default=True)
    media_quality = db.Column(db.String(10), default='auto')  
    
    is_private = db.Column(db.Boolean, default=False)
    allow_messages_from = db.Column(db.String(20), default='everyone')
    allow_tagging = db.Column(db.Boolean, default=True)
    show_activity_status = db.Column(db.Boolean, default=True)
    
    # Notifications
    notify_likes = db.Column(db.Boolean, default=True)
    notify_comments = db.Column(db.Boolean, default=True)
    notify_follows = db.Column(db.Boolean, default=True)
    notify_messages = db.Column(db.Boolean, default=True)
    notify_mentions = db.Column(db.Boolean, default=True)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    
    two_factor_enabled = db.Column(db.Boolean, default=False)
    last_password_change = db.Column(db.DateTime)
    
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
        return not self.has_blocked(user) and not user.has_blocked(self)

    def get_unread_message_count(self):
        return Message.query.filter_by(receiver_id=self.id, is_read=False).count()

    def get_unread_notification_count(self):
        return Notification.query.filter_by(user_id=self.id, is_read=False).count()

    def get_mutual_followers(self, other_user, limit=5):
        """Get mutual followers between current user and another user"""
        if not self.is_authenticated or not other_user:
            return []
        
        # Get the set of user ids that both self and other_user follow
        self_following = {user.id for user in self.followed.all()}
        other_following = {user.id for user in other_user.followed.all()}
        
        mutual_ids = self_following.intersection(other_following)
        
        # Return User objects for these ids, with optional limit
        query = User.query.filter(User.id.in_(mutual_ids))
        if limit:
            query = query.limit(limit)
        
        return query.all() if mutual_ids else []

    def get_follow_suggestions(self, limit=5):
        """Get suggested users to follow (users followed by people you follow)"""
        if not self.is_authenticated:
            return []
        
        # Get IDs of people the current user follows
        following_ids = [user.id for user in self.followed.all()]
        
        if not following_ids:
            # If not following anyone, return random users
            return User.query.filter(
                User.id != self.id,
                ~User.id.in_([b.id for b in self.blocked.all()])
            ).order_by(func.random()).limit(limit).all()
        
        # Get users followed by people the current user follows
        suggestions = User.query.join(followers, User.id == followers.c.followed_id).filter(
            followers.c.follower_id.in_(following_ids),
            User.id != self.id,
            ~User.id.in_(following_ids),
            ~User.id.in_([b.id for b in self.blocked.all()])
        ).group_by(User.id).order_by(func.count().desc()).limit(limit).all()
        
        return suggestions

    def get_post_count(self):
        """Get count of user's non-deleted posts"""
        return Post.query.filter_by(user_id=self.id, is_deleted=False).count()

    def get_like_count(self):
        """Get total likes received on user's posts"""
        return db.session.query(func.count(Like.id)).join(Post).filter(
            Post.user_id == self.id,
            Post.is_deleted == False
        ).scalar() or 0

    def is_mutual_follow(self, user):
        """Check if two users follow each other"""
        return self.is_following(user) and user.is_following(self)

    def get_common_groups(self, other_user):
        """Get common lists/groups both users are members of"""
        if not self.is_authenticated or not other_user:
            return []
        
        # Get lists where both users are members
        user_list_ids = [lm.list_id for lm in self.list_memberships.all()]
        other_list_ids = [lm.list_id for lm in other_user.list_memberships.all()]
        
        common_list_ids = set(user_list_ids).intersection(set(other_list_ids))
        
        if common_list_ids:
            return UserList.query.filter(UserList.id.in_(common_list_ids)).all()
        return []

    def update_last_seen(self):
        """Update user's last seen timestamp"""
        self.last_seen = datetime.utcnow()
        db.session.commit()

    def get_recent_activity(self, limit=10):
        """Get user's recent activity"""
        if not self.is_authenticated:
            return []
        
        # Get recent posts, likes, and comments
        recent_posts = Post.query.filter_by(
            user_id=self.id, 
            is_deleted=False
        ).order_by(Post.created_at.desc()).limit(limit//2).all()
        
        recent_likes = Like.query.join(Post).filter(
            Like.user_id == self.id,
            Post.is_deleted == False
        ).order_by(Like.created_at.desc()).limit(limit//2).all()
        
        recent_comments = Comment.query.filter_by(
            user_id=self.id,
            is_deleted=False
        ).order_by(Comment.created_at.desc()).limit(limit//2).all()
        
        # Combine and sort by date
        activity = []
        for post in recent_posts:
            activity.append({
                'type': 'post',
                'content': post.content[:100],
                'created_at': post.created_at,
                'link': f'/post/{post.id}'
            })
        
        for like in recent_likes:
            activity.append({
                'type': 'like',
                'content': f"Liked {like.post.author.username}'s post",
                'created_at': like.created_at,
                'link': f'/post/{like.post.id}'
            })
        
        for comment in recent_comments:
            activity.append({
                'type': 'comment',
                'content': comment.content[:100],
                'created_at': comment.created_at,
                'link': f'/post/{comment.post.id}'
            })
        
        # Sort by creation date, most recent first
        activity.sort(key=lambda x: x['created_at'], reverse=True)
        return activity[:limit]
    
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime)
    
    # Relationships
    media = db.relationship('PostMedia', backref='post', lazy='dynamic', cascade='all, delete-orphan')
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
    
class PostMedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    media_url = db.Column(db.String(500), nullable=False)
    media_type = db.Column(db.String(10), default='image')
    order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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


class Reel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    video_url = db.Column(db.String(500), nullable=False)
    thumbnail_url = db.Column(db.String(500))
    caption = db.Column(db.Text)
    duration = db.Column(db.Float)
    music = db.Column(db.String(200))
    location = db.Column(db.String(200))
    views_count = db.Column(db.Integer, default=0)
    likes_count = db.Column(db.Integer, default=0)
    comments_count = db.Column(db.Integer, default=0)
    shares_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_archived = db.Column(db.Boolean, default=False)
    
    likes = db.relationship('ReelLike', backref='reel', lazy='dynamic', cascade='all, delete-orphan')
    comments = db.relationship('ReelComment', backref='reel', lazy='dynamic', cascade='all, delete-orphan')
    views = db.relationship('ReelView', backref='reel', lazy='dynamic', cascade='all, delete-orphan')

class ReelLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reel_id = db.Column(db.Integer, db.ForeignKey('reel.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'reel_id', name='unique_reel_like'),)

class ReelComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reel_id = db.Column(db.Integer, db.ForeignKey('reel.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)

class ReelView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reel_id = db.Column(db.Integer, db.ForeignKey('reel.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    duration_watched = db.Column(db.Float)
    __table_args__ = (db.UniqueConstraint('user_id', 'reel_id', name='unique_reel_view'),)

# ============ STATUS MODELS ============
class Status(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    media_type = db.Column(db.String(10), nullable=False)
    media_url = db.Column(db.String(500))
    text = db.Column(db.Text)
    background_color = db.Column(db.String(20))
    text_color = db.Column(db.String(20))
    font_size = db.Column(db.Integer, default=24)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    views_count = db.Column(db.Integer, default=0)
    
    views = db.relationship('StatusView', backref='status', lazy='dynamic', cascade='all, delete-orphan')

class StatusView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status_id = db.Column(db.Integer, db.ForeignKey('status.id'), nullable=False)
    viewed_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'status_id', name='unique_status_view'),)


class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False, unique=True)
    title = db.Column(db.String(500), nullable=False)  # Poll title/description
    poll_type = db.Column(db.String(20), default='single_choice')  # single_choice, multiple_choice, ranked, quiz
    duration_hours = db.Column(db.Integer, default=24)
    ends_at = db.Column(db.DateTime, nullable=False)
    total_votes = db.Column(db.Integer, default=0)
    max_questions = db.Column(db.Integer, default=4)  # Maximum questions user can add
    max_options_per_question = db.Column(db.Integer, default=4)  # Maximum options per question
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_archived = db.Column(db.Boolean, default=False)
    
    # Relationships
    questions = db.relationship('PollQuestion', backref='poll', lazy='dynamic', cascade='all, delete-orphan')
    votes = db.relationship('PollVote', backref='poll', lazy='dynamic', cascade='all, delete-orphan')

class PollQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    question_text = db.Column(db.String(500), nullable=False)
    question_type = db.Column(db.String(20), default='text')  # text, image, video, gif
    media_url = db.Column(db.String(500))
    is_required = db.Column(db.Boolean, default=True)
    allow_multiple_choices = db.Column(db.Boolean, default=False)
    max_selections = db.Column(db.Integer, default=1)
    display_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    options = db.relationship('PollOption', backref='question', lazy='dynamic', cascade='all, delete-orphan')
    votes = db.relationship('PollVote', backref='question', lazy='dynamic', cascade='all, delete-orphan')

class PollOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('poll_question.id'), nullable=False)
    option_text = db.Column(db.String(500), nullable=False)
    option_type = db.Column(db.String(20), default='text')  # text, image, emoji
    media_url = db.Column(db.String(500))
    emoji = db.Column(db.String(10))  # For emoji options
    is_correct = db.Column(db.Boolean, default=False)  # For quiz polls
    vote_count = db.Column(db.Integer, default=0)
    display_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    votes = db.relationship('PollVote', backref='option', lazy='dynamic', cascade='all, delete-orphan')

class PollVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('poll_question.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('poll_option.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    selected_text = db.Column(db.String(500))  # For custom answer
    rank_position = db.Column(db.Integer)  # For ranked polls
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('poll_id', 'question_id', 'user_id', name='unique_poll_question_vote'),)

# Add this for quiz polls results
class PollResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, default=0)
    total_questions = db.Column(db.Integer, default=0)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint('poll_id', 'user_id', name='unique_poll_result'),)
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
    if len(password) < 5:
        return "Password must be at least 6 characters long"
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
        # Check if viewing a blocked user's content COMING SOON
        pass

"""offline issues"""
@app.after_request
def add_cache_headers(response):
    if response.mimetype in ['image/png', 'image/jpeg', 'image/gif', 'video/mp4', 'video/quicktime']:
        response.cache_control.max_age = 604800  # 7 days
        response.cache_control.public = True
    return response


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



@app.route('/post', methods=['POST','GET'])
@login_required
def create_post():
    content = request.form.get('content', '').strip()
    image = request.files.get('image')
    
    # Check for poll data
    has_poll = request.form.get('has_poll') == 'true'
    poll_title = request.form.get('poll_title', '').strip()
    poll_type = request.form.get('poll_type', 'single_choice')
    poll_duration = request.form.get('poll_duration', '24', type=int)
    
    # Get poll configuration
    max_questions = request.form.get('max_questions', 4, type=int)
    max_options_per_question = request.form.get('max_options_per_question', 4, type=int)
    
    if not content and not image and not has_poll:
        flash('Post cannot be empty.', 'danger')
        return redirect(url_for('feed'))
    
    if len(content) > 280:
        flash('Post cannot exceed 280 characters.', 'danger')
        return redirect(url_for('feed'))
    
    # Validate poll
    if has_poll:
        if not poll_title or len(poll_title.strip()) == 0:
            flash('Poll title cannot be empty.', 'danger')
            return redirect(url_for('feed'))
        
        # Validate poll configuration
        if max_questions < 1 or max_questions > 10:
            flash('You can add 1-10 questions in a poll.', 'danger')
            return redirect(url_for('feed'))
        
        if max_options_per_question < 2 or max_options_per_question > 8:
            flash('Each question can have 2-8 options.', 'danger')
            return redirect(url_for('feed'))
        
        if poll_duration not in [1, 3, 6, 12, 24, 48, 72, 168]:
            poll_duration = 24
        
        # Validate each question
        for q_num in range(1, max_questions + 1):
            question_text = request.form.get(f'question_{q_num}_text', '').strip()
            
            # Skip empty questions
            if not question_text and q_num == 1:
                flash('First question cannot be empty.', 'danger')
                return redirect(url_for('feed'))
            elif not question_text:
                max_questions = q_num - 1  # Adjust max questions based on actual filled questions
                break
            
            # Validate options for this question
            question_options = request.form.getlist(f'question_{q_num}_options[]')
            valid_options = [opt.strip() for opt in question_options if opt.strip()]
            
            if len(valid_options) < 2:
                flash(f'Question {q_num} must have at least 2 options.', 'danger')
                return redirect(url_for('feed'))
            
            if len(valid_options) > max_options_per_question:
                flash(f'Question {q_num} can have at most {max_options_per_question} options.', 'danger')
                return redirect(url_for('feed'))
            
            # Check for duplicate options in this question
            if len(valid_options) != len(set(valid_options)):
                flash(f'Question {q_num} has duplicate options.', 'danger')
                return redirect(url_for('feed'))
    
    # Create post
    post = Post(content=content, user_id=current_user.id)
    
    if image and allowed_file(image.filename):
        filename = secure_filename(f"{secrets.token_hex(8)}_{image.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'posts', filename)
        
        # Prevent overwriting
        counter = 1
        while os.path.exists(filepath):
            name, ext = os.path.splitext(filename)
            filename = f"{name}_{counter}{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'posts', filename)
            counter += 1
        
        image.save(filepath)
        post.image = filename
    
    db.session.add(post)
    db.session.flush()
    
    # Create poll with multiple questions
    if has_poll and max_questions > 0:
        ends_at = datetime.utcnow() + timedelta(hours=poll_duration)
        
        poll = Poll(
            post_id=post.id,
            title=poll_title,
            poll_type=poll_type,
            duration_hours=poll_duration,
            ends_at=ends_at,
            max_questions=max_questions,
            max_options_per_question=max_options_per_question
        )
        db.session.add(poll)
        db.session.flush()
        
        # Add questions and their options
        for q_num in range(1, max_questions + 1):
            question_text = request.form.get(f'question_{q_num}_text', '').strip()
            question_type = request.form.get(f'question_{q_num}_type', 'text')
            allow_multiple = request.form.get(f'question_{q_num}_allow_multiple', 'false') == 'true'
            max_selections = request.form.get(f'question_{q_num}_max_selections', 1, type=int)
            
            # Skip if question is empty
            if not question_text:
                continue
            
            # Handle question media upload
            question_media = request.files.get(f'question_{q_num}_media')
            question_media_url = None
            
            if question_media and allowed_file(question_media.filename):
                media_filename = secure_filename(f"poll_q{q_num}_{secrets.token_hex(4)}_{question_media.filename}")
                media_path = os.path.join(app.config['UPLOAD_FOLDER'], 'polls', 'questions', media_filename)
                question_media.save(media_path)
                question_media_url = media_filename
            
            question = PollQuestion(
                poll_id=poll.id,
                question_text=question_text,
                question_type=question_type,
                media_url=question_media_url,
                allow_multiple_choices=allow_multiple,
                max_selections=max_selections if allow_multiple else 1,
                display_order=q_num - 1
            )
            db.session.add(question)
            db.session.flush()
            
            # Add options for this question
            question_options = request.form.getlist(f'question_{q_num}_options[]')
            option_media_files = request.files.getlist(f'question_{q_num}_option_media[]')
            
            for opt_num, (option_text, option_media) in enumerate(zip(question_options, option_media_files)):
                option_text = option_text.strip()
                if not option_text:
                    continue
                
                option_type = request.form.get(f'question_{q_num}_option_{opt_num}_type', 'text')
                is_correct = request.form.get(f'question_{q_num}_option_{opt_num}_correct', 'false') == 'true'
                option_emoji = request.form.get(f'question_{q_num}_option_{opt_num}_emoji', '')
                
                option_media_url = None
                if option_media and allowed_file(option_media.filename):
                    opt_media_filename = secure_filename(f"poll_q{q_num}_opt{opt_num}_{secrets.token_hex(4)}_{option_media.filename}")
                    opt_media_path = os.path.join(app.config['UPLOAD_FOLDER'], 'polls', 'options', opt_media_filename)
                    option_media.save(opt_media_path)
                    option_media_url = opt_media_filename
                
                option = PollOption(
                    question_id=question.id,
                    option_text=option_text,
                    option_type=option_type,
                    media_url=option_media_url,
                    emoji=option_emoji,
                    is_correct=is_correct,
                    display_order=opt_num
                )
                db.session.add(option)
    
    # Process hashtags
    hashtags = extract_hashtags(content)
    for tag in hashtags[:10]:
        tag = tag.lower().strip()
        if not tag:
            continue
            
        existing = Hashtag.query.filter_by(tag=tag).first()
        if existing:
            existing.count += 1
            existing.last_used = datetime.utcnow()
        else:
            existing = Hashtag(tag=tag)
            db.session.add(existing)
            db.session.flush()
        
        existing_link = PostHashtag.query.filter_by(
            post_id=post.id,
            hashtag_id=existing.id
        ).first()
        
        if not existing_link:
            post_hashtag = PostHashtag(post_id=post.id, hashtag_id=existing.id)
            db.session.add(post_hashtag)
    
    # Process mentions
    mentions = extract_mentions(content)
    for username in mentions:
        mentioned_user = User.query.filter_by(username=username).first()
        if mentioned_user and mentioned_user.id != current_user.id and current_user.can_interact_with(mentioned_user):
            existing_notif = Notification.query.filter_by(
                user_id=mentioned_user.id,
                notification_type='mention',
                link=f"/post/{post.id}"
            ).first()
            
            if not existing_notif:
                notif = Notification(
                    user_id=mentioned_user.id,
                    content=f"{current_user.username} mentioned you in a post",
                    link=f"/post/{post.id}",
                    notification_type='mention'
                )
                db.session.add(notif)
    
    # Handle GIF if provided
    gif_url = request.form.get('gif_url', '').strip()
    if gif_url:
        if not content:
            content = f"<div class='gif-embed'><img src='{gif_url}' alt='GIF' class='img-fluid rounded'></div>"
        else:
            content += f"<div class='gif-embed'><img src='{gif_url}' alt='GIF' class='img-fluid rounded'></div>"
        post.content = content
    
    try:
        db.session.commit()
        
        # Send notification to followers for new poll post
        if has_poll:
            followers = current_user.followers.all()
            for follower in followers[:50]:
                if follower.id != current_user.id and current_user.can_interact_with(follower):
                    notif = Notification(
                        user_id=follower.id,
                        content=f"{current_user.username} created a new poll: {poll_title}",
                        link=f"/post/{post.id}",
                        notification_type='poll'
                    )
                    db.session.add(notif)
            
            db.session.commit()
            flash(f'Poll created with {max_questions} question(s)!', 'success')
        else:
            flash('Post created successfully!', 'success')
        
        return redirect(url_for('view_post', post_id=post.id))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating post: {str(e)}")
        flash('An error occurred while creating the post. Please try again.', 'danger')
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
    
@app.route('/post/<int:post_id>/poll/vote', methods=['POST'])
@login_required
def vote_poll(post_id):
    """Vote on a poll"""
    try:
        poll = Poll.query.filter_by(post_id=post_id).first()
        if not poll:
            return jsonify({'error': 'Poll not found'}), 404
        
        if poll.ends_at < datetime.utcnow():
            return jsonify({'error': 'Poll has ended'}), 400
        
        option_id = request.json.get('option_id')
        if not option_id:
            return jsonify({'error': 'Option ID is required'}), 400
        
        option = PollOption.query.get(option_id)
        if not option or option.poll_id != poll.id:
            return jsonify({'error': 'Invalid option'}), 400
        
        # Check if already voted
        existing_vote = PollVote.query.filter_by(
            poll_id=poll.id,
            user_id=current_user.id
        ).first()
        
        if existing_vote:
            # Change vote
            old_option = PollOption.query.get(existing_vote.option_id)
            old_option.vote_count -= 1
            existing_vote.option_id = option_id
            option.vote_count += 1
        else:
            # New vote
            vote = PollVote(
                poll_id=poll.id,
                option_id=option_id,
                user_id=current_user.id
            )
            db.session.add(vote)
            option.vote_count += 1
            poll.total_votes += 1
        
        db.session.commit()
        
        # Get updated poll data
        poll_data = get_poll_data(poll)
        
        return jsonify({
            'success': True,
            'poll': poll_data,
            'user_voted_option': option_id,
            'message': 'Vote recorded successfully' if not existing_vote else 'Vote changed successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/post/<int:post_id>/poll/results')
@login_required
def get_poll_results(post_id):
    """Get detailed poll results"""
    try:
        poll = Poll.query.filter_by(post_id=post_id).first()
        if not poll:
            return jsonify({'error': 'Poll not found'}), 404
        
        poll_data = get_poll_data(poll)
        
        # Get voters for each option
        options_with_voters = []
        for option in poll.options.order_by(PollOption.id).all():
            votes = PollVote.query.filter_by(option_id=option.id).order_by(PollVote.voted_at.desc()).limit(20).all()
            
            voters = []
            for vote in votes:
                user = User.query.get(vote.user_id)
                if user:
                    voters.append({
                        'id': user.id,
                        'username': user.username,
                        'profile_picture': user.profile_picture,
                        'voted_at': vote.voted_at.isoformat()
                    })
            
            options_with_voters.append({
                'id': option.id,
                'text': option.option_text,
                'vote_count': option.vote_count,
                'percentage': round((option.vote_count / poll.total_votes * 100) if poll.total_votes > 0 else 0, 1),
                'voters': voters
            })
        
        return jsonify({
            'poll': poll_data,
            'options': options_with_voters,
            'total_votes': poll.total_votes,
            'time_left': get_time_remaining(poll.ends_at)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/post/<int:post_id>/poll/end', methods=['POST'])
@login_required
def end_poll_early(post_id):
    """End a poll early (only by post author or admin)"""
    try:
        poll = Poll.query.filter_by(post_id=post_id).first()
        if not poll:
            return jsonify({'error': 'Poll not found'}), 404
        
        post = Post.query.get(post_id)
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        
        # Check permission
        if post.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'Only the post author or admin can end the poll early'}), 403
        
        # End poll now
        poll.ends_at = datetime.utcnow()
        db.session.commit()
        
        poll_data = get_poll_data(poll)
        
        return jsonify({
            'success': True,
            'poll': poll_data,
            'message': 'Poll ended successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/poll/trending')
@login_required
def trending_polls():
    """Get trending polls"""
    try:
        # Get active polls from followed users
        followed_users = current_user.followed.all()
        followed_ids = [u.id for u in followed_users] + [current_user.id]
        
        active_polls = Poll.query.join(Post).filter(
            Post.user_id.in_(followed_ids),
            Poll.ends_at > datetime.utcnow(),
            Poll.is_archived == False
        ).order_by(
            Poll.total_votes.desc(),
            Poll.created_at.desc()
        ).limit(10).all()
        
        polls_data = []
        for poll in active_polls:
            user_voted = PollVote.query.filter_by(
                poll_id=poll.id,
                user_id=current_user.id
            ).first() is not None
            
            polls_data.append({
                'id': poll.id,
                'post_id': poll.post_id,
                'question': poll.question,
                'ends_at': poll.ends_at.isoformat(),
                'total_votes': poll.total_votes,
                'time_left': get_time_remaining(poll.ends_at),
                'user_voted': user_voted,
                'author': {
                    'id': poll.post.author.id,
                    'username': poll.post.author.username,
                    'profile_picture': poll.post.author.profile_picture
                }
            })
        
        return jsonify({'polls': polls_data})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_poll_data(poll):
    """Helper function to get poll data for API responses"""
    options = []
    for option in poll.options.order_by(PollOption.id).all():
        options.append({
            'id': option.id,
            'text': option.option_text,
            'vote_count': option.vote_count,
            'percentage': round((option.vote_count / poll.total_votes * 100) if poll.total_votes > 0 else 0, 1)
        })
    
    user_voted_option = None
    user_vote = PollVote.query.filter_by(
        poll_id=poll.id,
        user_id=current_user.id
    ).first()
    
    if user_vote:
        user_voted_option = user_vote.option_id
    
    return {
        'id': poll.id,
        'post_id': poll.post_id,
        'question': poll.question,
        'duration_hours': poll.duration_hours,
        'ends_at': poll.ends_at.isoformat(),
        'total_votes': poll.total_votes,
        'is_active': poll.ends_at > datetime.utcnow(),
        'time_left': get_time_remaining(poll.ends_at),
        'options': options,
        'user_voted': user_voted_option is not None,
        'user_voted_option': user_voted_option,
        'can_end_early': poll.post.author.id == current_user.id or current_user.is_admin
    }

def get_time_remaining(ends_at):
    """Calculate time remaining for poll"""
    now = datetime.utcnow()
    if ends_at <= now:
        return "Ended"
    
    diff = ends_at - now
    
    if diff.days > 0:
        return f"{diff.days}d {diff.seconds // 3600}h"
    elif diff.seconds >= 3600:
        hours = diff.seconds // 3600
        minutes = (diff.seconds % 3600) // 60
        return f"{hours}h {minutes}m"
    else:
        minutes = diff.seconds // 60
        if minutes > 0:
            return f"{minutes}m"
        else:
            return "Less than a minute"

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
    
    # Get posts with images for media section
    posts_with_images = Post.query.filter_by(
        user_id=user.id,
        is_deleted=False
    ).filter(Post.image.isnot(None)).order_by(Post.created_at.desc()).all()
    
    # Calculate stats
    total_likes = sum(post.like_count() for post in posts)
    total_posts = len(posts)
    total_followers = user.followers.count()
    total_following = user.followed.count()
    
    # Check relationships
    is_following = current_user.is_following(user)
    is_blocked = current_user.has_blocked(user)
    is_blocked_by = user.has_blocked(current_user)
    
    # Get mutual followers - simplified version
    mutual_followers = []
    if current_user.is_authenticated and user != current_user:
        # Users that both current_user and user follow
        current_following = {u.id for u in current_user.followed}
        user_following = {u.id for u in user.followed}
        mutual_ids = current_following.intersection(user_following)
        if mutual_ids:
            mutual_followers = User.query.filter(User.id.in_(mutual_ids)).limit(5).all()
    
    # Get user suggestions (not followed, not blocked)
    blocked_ids = [b.id for b in current_user.blocked.all()]
    blocked_by_ids = [b.id for b in current_user.blocked_by.all()]
    followed_ids = [u.id for u in current_user.followed.all()] + [current_user.id]
    
    suggestions = User.query.filter(
        User.id != current_user.id,
        User.id != user.id,
        ~User.id.in_(followed_ids),
        ~User.id.in_(blocked_ids),
        ~User.id.in_(blocked_by_ids)
    ).order_by(func.random()).limit(5).all()
    
    # Create recent activity data (simplified)
    recent_activity = []
    
    return render_template('profile.html', 
                         user=user, 
                         posts=posts, 
                         posts_with_images=posts_with_images[:6],
                         pinned_post=pinned_post,
                         total_likes=total_likes,
                         total_posts=total_posts,
                         total_followers=total_followers,
                         total_following=total_following,
                         is_following=is_following,
                         is_blocked=is_blocked,
                         is_blocked_by=is_blocked_by,
                         mutual_followers=mutual_followers,
                         suggestions=suggestions,
                         recent_activity=recent_activity)
#                    following=following_list)

@app.route('/profile/<username>/media')
@login_required
def profile_media(username):
    """Show user's media posts"""
    user = User.query.filter_by(username=username).first_or_404()
    
    if not current_user.can_interact_with(user):
        flash('You cannot view this profile.', 'danger')
        return redirect(url_for('feed'))
    
    posts_with_images = Post.query.filter_by(
        user_id=user.id,
        is_deleted=False
    ).filter(Post.image.isnot(None)).order_by(
        Post.created_at.desc()
    ).all()
    
    # Convert posts to JSON-safe format for JavaScript
    posts_json = []
    for post in posts_with_images:
        posts_json.append({
            'id': post.id,
            'image': post.image,
            'content': post.content,
            'created_at': post.created_at.isoformat(),
            'like_count': post.like_count(),
            'comment_count': post.comment_count(),
            'author': {
                'username': post.author.username,
                'profile_picture': post.author.profile_picture
            }
        })
    
    return render_template('profile_media.html', 
                         user=user, 
                         posts_with_images=posts_with_images,
                         posts_json=posts_json)

@app.route('/profile/<username>/lists')
@login_required
def profile_lists(username):
    """Show user's lists"""
    user = User.query.filter_by(username=username).first_or_404()
    
    if not current_user.can_interact_with(user):
        flash('You cannot view this profile.', 'danger')
        return redirect(url_for('feed'))
    
    user_lists = UserList.query.filter_by(user_id=user.id).all()
    
    return render_template('profile_lists.html', 
                         user=user, 
                         user_lists=user_lists)

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


def generate_follow_token(user_id):
    secret = app.config['SECRET_KEY'].encode()
    message = str(user_id).encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()

def generate_qr_image(user_id):
    token = generate_follow_token(user_id)
    follow_url = url_for('handle_follow_qr', user_id=user_id, token=token, _external=True)
    
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5,
        error_correction=qrcode.constants.ERROR_CORRECT_H
    )
    qr.add_data(follow_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
    
    # Branded logo with "C"
    logo_size = 60
    logo = Image.new('RGBA', (logo_size, logo_size), (255,255,255,0))
    draw = ImageDraw.Draw(logo)
    draw.ellipse((0,0,logo_size-1,logo_size-1), fill=(29,161,242,255))
    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except:
        font = ImageFont.load_default()
    bbox = draw.textbbox((0,0), "C", font=font)
    text_width = bbox[2]-bbox[0]; text_height = bbox[3]-bbox[1]
    position = ((logo_size - text_width)//2, (logo_size - text_height)//2)
    draw.text(position, "C", fill="white", font=font)
    img.paste(logo, ((img.width - logo_size)//2, (img.height - logo_size)//2), logo)
    
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return buffer

@app.route('/profile/qr')
@login_required
def profile_qr():
    buffer = generate_qr_image(current_user.id)
    return send_file(buffer, mimetype='image/png', download_name=f'follow_{current_user.username}.png')

@app.route('/profile/<username>/qr')
def profile_qr_view(username):
    user = User.query.filter_by(username=username).first_or_404()
    buffer = generate_qr_image(user.id)
    return send_file(buffer, mimetype='image/png')

@app.route('/follow-qr/<int:user_id>/<token>')
def handle_follow_qr(user_id, token):
    expected = generate_follow_token(user_id)
    if not hmac.compare_digest(token, expected):
        abort(400, description="Invalid or expired QR code")
    user = User.query.get_or_404(user_id)
    if not current_user.is_authenticated:
        flash('Please log in to follow via QR.', 'info')
        return redirect(url_for('login', next=request.full_path))
    if current_user.id == user_id:
        flash("Can't follow yourself.", 'warning')
        return redirect(url_for('profile', username=user.username))
    if not current_user.is_following(user) and current_user.can_interact_with(user):
        current_user.follow(user)
        notif = Notification(
            user_id=user.id,
            content=f"{current_user.username} followed you via QR code",
            link=f"/profile/{current_user.username}",
            notification_type='follow'
        )
        db.session.add(notif)
        db.session.commit()
        flash(f"You are now following {user.username}!", 'success')
    elif current_user.is_following(user):
        flash(f"You already follow {user.username}.", 'info')
    return redirect(url_for('profile', username=user.username))

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

@app.route('/api/user/lists')
@login_required
def get_user_lists():
    """Get user's lists for adding other users"""
    lists = UserList.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': lst.id,
        'name': lst.name,
        'description': lst.description,
        'member_count': lst.members.count()
    } for lst in lists])

@app.route('/profile/<username>/followers')
@login_required
def profile_followers(username):
    """Show user's followers"""
    user = User.query.filter_by(username=username).first_or_404()
    
    if not current_user.can_interact_with(user):
        flash('You cannot view this profile.', 'danger')
        return redirect(url_for('feed'))
    
    followers = user.followers.all()
    
    return render_template('profile_followers.html', 
                         user=user, 
                         followers=followers)

@app.route('/profile/<username>/following')
@login_required
def profile_following(username):
    """Show users this user is following"""
    user = User.query.filter_by(username=username).first_or_404()
    
    if not current_user.can_interact_with(user):
        flash('You cannot view this profile.', 'danger')
        return redirect(url_for('feed'))
    
    following = user.followed.all()
    
    return render_template('profile_following.html', 
                         user=user, 
                         following=following)



@app.route('/api/search/live')
@login_required
def live_search():
    """Live search API for autocomplete"""
    query = request.args.get('q', '').strip()
    
    if len(query) < 2:
        return jsonify({'users': [], 'hashtags': []})
    
    # Search users
    users = User.query.filter(
        User.username.contains(query),
        User.id != current_user.id,
        ~User.id.in_([b.id for b in current_user.blocked.all()]),
        ~User.id.in_([b.id for b in current_user.blocked_by.all()])
    ).limit(10).all()
    
    # Search hashtags
    hashtags = Hashtag.query.filter(
        Hashtag.tag.contains(query[1:] if query.startswith('#') else query)
    ).order_by(Hashtag.count.desc()).limit(5).all()
    
    return jsonify({
        'users': [{
            'id': user.id,
            'username': user.username,
            'profile_picture': user.profile_picture,
            'is_verified': user.is_verified,
            'follower_count': user.followers.count()
        } for user in users],
        'hashtags': [{
            'tag': hashtag.tag,
            'count': hashtag.count
        } for hashtag in hashtags]
    })

@app.route('/notifications/count')
@login_required
def notification_count():
    """Get unread notification count"""
    count = current_user.get_unread_notification_count()
    return jsonify({'count': count})

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
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'mp4', 'mov', 'avi', 'mkv'}
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
    if len(username) < 3 or len(username) > 30:
        return "Username must be between 3 and 30 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return "Username can only contain letters, numbers, and underscores"
    return None

# ============ CONTEXT PROCESSORS ============
@app.context_processor
def utility_processor():
    def has_active_status(user_id):
        """Check if a user has active status"""
        if not user_id:
            return False
        return Status.query.filter(
            Status.user_id == user_id,
            Status.expires_at > datetime.utcnow()
        ).count() > 0
    
    def get_active_status_count(user_id):
        """Get count of active statuses for a user"""
        if not user_id:
            return 0
        return Status.query.filter(
            Status.user_id == user_id,
            Status.expires_at > datetime.utcnow()
        ).count()
    
    def get_user_avatar_url(user):
        """Get user avatar URL with fallback"""
        if user and user.profile_picture and user.profile_picture != 'default.jpg':
            return url_for('static', filename='uploads/profiles/' + user.profile_picture)
        elif user:
            return f'https://ui-avatars.com/api/?name={user.username}&background=1d9bf0&color=fff'
        return ''
    
    def get_followed_users_with_status(current_user):
        """Get followed users with active statuses"""
        if not current_user or not current_user.is_authenticated:
            return []
        
        followed_users = current_user.followed.all()
        users_with_status = []
        
        for user in followed_users:
            active_statuses = Status.query.filter(
                Status.user_id == user.id,
                Status.expires_at > datetime.utcnow()
            ).order_by(Status.created_at.desc()).all()
            
            if active_statuses:
                viewed = StatusView.query.filter(
                    StatusView.user_id == current_user.id,
                    StatusView.status_id.in_([s.id for s in active_statuses])
                ).first() is not None
                
                users_with_status.append({
                    'user': user,
                    'statuses': active_statuses,
                    'viewed': viewed,
                    'count': len(active_statuses)
                })
        
        return users_with_status
    
    def get_status_stories_for_feed(current_user):
        """Get status stories for the feed page"""
        if not current_user or not current_user.is_authenticated:
            return []
        
        followed_users = current_user.followed.all()
        followed_ids = [u.id for u in followed_users] + [current_user.id]
        
        users_with_status = []
        for user_id in followed_ids:
            user = User.query.get(user_id)
            if not user:
                continue
                
            active_statuses = Status.query.filter(
                Status.user_id == user_id,
                Status.expires_at > datetime.utcnow()
            ).order_by(Status.created_at.desc()).all()
            
            if active_statuses:
                viewed_status_ids = [sv.status_id for sv in 
                                   StatusView.query.filter_by(user_id=current_user.id).all()]
                
                users_with_status.append({
                    'user': user,
                    'statuses': active_statuses,
                    'has_unviewed': any(s.id not in viewed_status_ids for s in active_statuses),
                    'count': len(active_statuses)
                })
        
        return users_with_status
    
    return dict(
        has_active_status=has_active_status,
        get_active_status_count=get_active_status_count,
        get_user_avatar_url=get_user_avatar_url,
        get_followed_users_with_status=get_followed_users_with_status,
        get_status_stories_for_feed=get_status_stories_for_feed,
        datetime=datetime
    )

# ============ BEFORE REQUEST ============
@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        if current_user.is_online and (datetime.utcnow() - current_user.last_seen).seconds > 300:
            current_user.is_online = False
        db.session.commit()

@app.before_request
def cleanup_expired_statuses():
    """Clean up expired statuses"""
    Status.query.filter(Status.expires_at < datetime.utcnow()).delete(synchronize_session=False)
    db.session.commit()

# ============ REELS ROUTES ============
@app.route('/reels')
@login_required
def reels_feed():
    """Reels feed page"""
    page = request.args.get('page', 1, type=int)
    
    followed_users = current_user.followed.all()
    followed_ids = [u.id for u in followed_users] + [current_user.id]
    
    blocked_ids = [b.id for b in current_user.blocked.all()]
    blocked_by_ids = [b.id for b in current_user.blocked_by.all()]
    
    reels_query = Reel.query.filter(
        Reel.user_id.in_(followed_ids),
        Reel.is_archived == False,
        ~Reel.user_id.in_(blocked_ids),
        ~Reel.user_id.in_(blocked_by_ids)
    ).order_by(Reel.created_at.desc())
    
    reels = reels_query.paginate(page=page, per_page=10, error_out=False)
    
    trending_reels = Reel.query.filter(
        Reel.is_archived == False,
        ~Reel.user_id.in_(blocked_ids),
        ~Reel.user_id.in_(blocked_by_ids)
    ).order_by(Reel.views_count.desc(), Reel.likes_count.desc()).limit(5).all()
    
    return render_template('reels/feed.html', reels=reels, trending_reels=trending_reels)

@app.route('/reels/upload', methods=['GET', 'POST'])
@login_required
def upload_reel():
    """Upload a new reel"""
    if request.method == 'POST':
        video = request.files.get('video')
        caption = request.form.get('caption', '').strip()
        music = request.form.get('music', '').strip()
        location = request.form.get('location', '').strip()
        
        if not video or not allowed_file(video.filename):
            flash('Please upload a valid video file (MP4, MOV, AVI, MKV).', 'danger')
            return redirect(request.url)
        
        filename = secure_filename(f"reel_{current_user.id}_{datetime.utcnow().timestamp()}_{video.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'reels', filename)
        video.save(filepath)
        
        thumbnail_filename = f"thumb_{filename.rsplit('.', 1)[0]}.jpg"
        thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], 'reel_thumbnails', thumbnail_filename)
        
        try:
            from PIL import Image, ImageDraw
            img = Image.new('RGB', (640, 1136), color=(73, 109, 137))
            draw = ImageDraw.Draw(img)
            draw.text((320, 568), "REEL", fill=(255, 255, 255))
            img.save(thumbnail_path, 'JPEG')
        except:
            pass
        
        reel = Reel(
            user_id=current_user.id,
            video_url=filename,
            thumbnail_url=thumbnail_filename,
            caption=caption,
            music=music,
            location=location,
            duration=15.0
        )
        
        db.session.add(reel)
        db.session.commit()
        
        flash('Reel uploaded successfully!', 'success')
        return redirect(url_for('view_reel', reel_id=reel.id))
    
    return render_template('reels/upload.html')

@app.route('/reel/<int:reel_id>')
@login_required
def view_reel(reel_id):
    """View a single reel"""
    reel = Reel.query.get_or_404(reel_id)
    
    if not current_user.can_interact_with(reel.user):
        flash('You cannot view this reel.', 'danger')
        return redirect(url_for('reels_feed'))
    
    existing_view = ReelView.query.filter_by(
        user_id=current_user.id,
        reel_id=reel_id
    ).first()
    
    if not existing_view:
        view = ReelView(user_id=current_user.id, reel_id=reel_id)
        reel.views_count += 1
        db.session.add(view)
        db.session.commit()
    else:
        existing_view.created_at = datetime.utcnow()
        db.session.commit()
    
    comments = ReelComment.query.filter_by(
        reel_id=reel_id,
        is_deleted=False
    ).order_by(ReelComment.created_at.desc()).all()
    
    is_liked = ReelLike.query.filter_by(
        user_id=current_user.id,
        reel_id=reel_id
    ).first() is not None
    
    suggested_reels = Reel.query.filter(
        Reel.id != reel_id,
        Reel.is_archived == False,
        ~Reel.user_id.in_([b.id for b in current_user.blocked.all()])
    ).order_by(func.random()).limit(5).all()
    
    return render_template('reels/view.html', 
                         reel=reel, 
                         comments=comments,
                         is_liked=is_liked,
                         suggested_reels=suggested_reels)

@app.route('/reel/<int:reel_id>/like', methods=['POST'])
@login_required
def like_reel(reel_id):
    """Like/unlike a reel"""
    try:
        reel = Reel.query.get_or_404(reel_id)
        
        existing_like = ReelLike.query.filter_by(
            user_id=current_user.id,
            reel_id=reel_id
        ).first()
        
        if existing_like:
            db.session.delete(existing_like)
            reel.likes_count -= 1
            liked = False
        else:
            like = ReelLike(user_id=current_user.id, reel_id=reel_id)
            reel.likes_count += 1
            db.session.add(like)
            
            if reel.user_id != current_user.id:
                notif = Notification(
                    user_id=reel.user_id,
                    content=f"{current_user.username} liked your reel",
                    link=f"/reel/{reel_id}",
                    notification_type='reel_like'
                )
                db.session.add(notif)
            liked = True
        
        db.session.commit()
        
        return jsonify({
            'status': 'liked' if liked else 'unliked',
            'likes_count': reel.likes_count
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/reel/<int:reel_id>/comment', methods=['POST'])
@login_required
def comment_reel(reel_id):
    """Add comment to reel"""
    try:
        reel = Reel.query.get_or_404(reel_id)
        content = request.form.get('content', '').strip()
        
        if not content:
            return jsonify({'error': 'Comment cannot be empty'}), 400
        
        comment = ReelComment(
            user_id=current_user.id,
            reel_id=reel_id,
            content=content
        )
        
        reel.comments_count += 1
        db.session.add(comment)
        
        if reel.user_id != current_user.id:
            notif = Notification(
                user_id=reel.user_id,
                content=f"{current_user.username} commented on your reel",
                link=f"/reel/{reel_id}",
                notification_type='reel_comment'
            )
            db.session.add(notif)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'comment': {
                'id': comment.id,
                'content': content,
                'created_at': comment.created_at.isoformat(),
                'user': {
                    'username': current_user.username,
                    'profile_picture': current_user.profile_picture
                }
            },
            'comments_count': reel.comments_count
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/reel/<int:reel_id>/share', methods=['POST'])
@login_required
def share_reel(reel_id):
    """Share a reel"""
    try:
        reel = Reel.query.get_or_404(reel_id)
        reel.shares_count += 1
        db.session.commit()
        
        return jsonify({
            'success': True,
            'shares_count': reel.shares_count
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/reel/<int:reel_id>/delete', methods=['POST'])
@login_required
def delete_reel(reel_id):
    """Delete a reel"""
    try:
        reel = Reel.query.get_or_404(reel_id)
        
        if reel.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'error': 'You can only delete your own reels'}), 403
        
        reel.is_archived = True
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Reel deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ============ STATUS ROUTES ============
@app.route('/status/create', methods=['GET', 'POST'])
@login_required
def create_status():
    """Create a new status"""
    if request.method == 'POST':
        media_type = request.form.get('media_type', 'text')
        text = request.form.get('text', '').strip()
        background_color = request.form.get('background_color', '#000000')
        text_color = request.form.get('text_color', '#ffffff')
        font_size = request.form.get('font_size', 24, type=int)
        
        media_url = None
        if 'media' in request.files:
            media = request.files['media']
            if media and media.filename != '' and allowed_file(media.filename):
                filename = secure_filename(f"status_{current_user.id}_{datetime.utcnow().timestamp()}_{media.filename}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'statuses', filename)
                media.save(filepath)
                media_url = filename
        
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        status = Status(
            user_id=current_user.id,
            media_type=media_type,
            media_url=media_url,
            text=text,
            background_color=background_color,
            text_color=text_color,
            font_size=font_size,
            expires_at=expires_at
        )
        
        db.session.add(status)
        db.session.commit()
        
        flash('Status created! It will expire in 24 hours.', 'success')
        return redirect(url_for('feed'))
    
    return render_template('status/create.html')

@app.route('/status/<int:status_id>')
@login_required
def view_status(status_id):
    """View a status"""
    status = Status.query.get_or_404(status_id)
    
    if status.expires_at < datetime.utcnow():
        flash('This status has expired.', 'danger')
        return redirect(url_for('feed'))
    
    existing_view = StatusView.query.filter_by(
        user_id=current_user.id,
        status_id=status_id
    ).first()
    
    if not existing_view:
        view = StatusView(user_id=current_user.id, status_id=status_id)
        status.views_count += 1
        db.session.add(view)
        db.session.commit()
    
    next_statuses = Status.query.filter(
        Status.user_id == status.user_id,
        Status.id != status_id,
        Status.expires_at > datetime.utcnow()
    ).order_by(Status.created_at.asc()).all()
    
    return render_template('status/view.html', 
                         status=status, 
                         next_statuses=next_statuses)

@app.route('/status/feed')
@login_required
def status_feed():
    """View all statuses from followed users"""
    followed_users = current_user.followed.all()
    followed_ids = [u.id for u in followed_users] + [current_user.id]
    
    # Get sort parameter
    sort_type = request.args.get('sort', 'newest')
    
    # Query statuses
    query = Status.query.filter(
        Status.user_id.in_(followed_ids),
        Status.expires_at > datetime.utcnow()
    )
    
    # Apply sorting
    if sort_type == 'oldest':
        query = query.order_by(Status.created_at.asc())
    elif sort_type == 'most_views':
        query = query.order_by(Status.views_count.desc())
    else:  # newest
        query = query.order_by(Status.created_at.desc())
    
    statuses = query.all()
    
    # Group statuses by user
    statuses_by_user = {}
    total_active_statuses = 0
    total_views = 0
    
    for status in statuses:
        if status.user_id not in statuses_by_user:
            statuses_by_user[status.user_id] = []
        statuses_by_user[status.user_id].append(status)
        total_active_statuses += 1
        total_views += status.views_count
    
    # Get viewed status IDs
    viewed_status_ids = [sv.status_id for sv in 
                        StatusView.query.filter_by(user_id=current_user.id).all()]
    
    # Get top viewers for current user's statuses
    user_status_ids = [s.id for s in current_user.statuses]
    top_viewers_query = StatusView.query.filter(
        StatusView.status_id.in_(user_status_ids)
    ).group_by(StatusView.user_id).order_by(db.func.count().desc()).limit(5).all()
    
    top_viewers = []
    for viewer in top_viewers_query:
        user = User.query.get(viewer.user_id)
        if user:
            view_count = StatusView.query.filter(
                StatusView.user_id == viewer.user_id,
                StatusView.status_id.in_(user_status_ids)
            ).count()
            top_viewers.append({
                'user': user,
                'view_count': view_count
            })
    
    # Get recent viewers (last 5)
    recent_viewers_query = StatusView.query.filter(
        StatusView.status_id.in_(user_status_ids)
    ).order_by(StatusView.viewed_at.desc()).limit(5).all()
    
    recent_viewers = []
    for viewer in recent_viewers_query:
        user = User.query.get(viewer.user_id)
        if user and user.id != current_user.id:
            recent_viewers.append({
                'user': user,
                'viewed_at': viewer.viewed_at
            })
    
    # Calculate active statuses for current user
    current_user_active_statuses = Status.query.filter(
        Status.user_id == current_user.id,
        Status.expires_at > datetime.utcnow()
    ).count()
    
    # Calculate views for current user
    current_user_views_today = StatusView.query.join(Status).filter(
        Status.user_id == current_user.id,
        StatusView.viewed_at >= datetime.utcnow().date()
    ).count()
    
    current_user_total_views = StatusView.query.join(Status).filter(
        Status.user_id == current_user.id
    ).count()
    
    # Calculate days since joining
    days_since_joining = (datetime.utcnow() - current_user.created_at).days
    
    # Calculate average daily views
    avg_daily_views = 0
    if days_since_joining > 0:
        avg_daily_views = current_user_total_views / days_since_joining
    
    return render_template('status/feed.html',
                         statuses_by_user=statuses_by_user,
                         viewed_status_ids=viewed_status_ids,
                         total_active_statuses=total_active_statuses,
                         total_views=total_views,
                         top_viewers=top_viewers,
                         recent_viewers=recent_viewers,
                         current_user_active_statuses=current_user_active_statuses,
                         current_user_views_today=current_user_views_today,
                         current_user_total_views=current_user_total_views,
                         avg_daily_views=round(avg_daily_views, 2),
                         days_since_joining=days_since_joining,
                         sort_type=sort_type)
            
@app.route('/status/<int:status_id>/viewers')
@login_required
def status_viewers(status_id):
    """Get list of users who viewed the status"""
    status = Status.query.get_or_404(status_id)
    
    if status.user_id != current_user.id:
        flash('You can only see viewers of your own status.', 'danger')
        return redirect(url_for('feed'))
    
    viewers = User.query.join(StatusView).filter(
        StatusView.status_id == status_id
    ).order_by(StatusView.viewed_at.desc()).all()
    
    return render_template('status/viewers.html', status=status, viewers=viewers)

@app.route('/status/<int:status_id>/delete', methods=['POST'])
@login_required
def delete_status(status_id):
    """Delete a status"""
    try:
        status = Status.query.get_or_404(status_id)
        
        if status.user_id != current_user.id:
            return jsonify({'error': 'You can only delete your own status'}), 403
        
        db.session.delete(status)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Status deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ============ API ROUTES ============
@app.route('/api/followers/status')
@login_required
def get_followers_status():
    """Get active statuses from followed users"""
    try:
        followed_users = current_user.followed.all()
        followed_ids = [u.id for u in followed_users]
        
        yesterday = datetime.utcnow() - timedelta(hours=24)
        
        statuses = Status.query.filter(
            Status.user_id.in_(followed_ids),
            Status.created_at > yesterday
        ).order_by(Status.created_at.desc()).all()
        
        status_dict = {}
        for status in statuses:
            if status.user_id not in status_dict:
                status_dict[status.user_id] = {
                    'user': status.user,
                    'statuses': [],
                    'latest': status,
                    'count': 0
                }
            status_dict[status.user_id]['statuses'].append(status)
            status_dict[status.user_id]['count'] += 1
        
        viewed_status_ids = [sv.status_id for sv in 
                           StatusView.query.filter_by(user_id=current_user.id).all()]
        
        result = []
        for user_id, data in status_dict.items():
            latest_status = data['statuses'][0]
            result.append({
                'id': latest_status.id,
                'user': {
                    'id': data['user'].id,
                    'username': data['user'].username,
                    'profile_picture': data['user'].profile_picture
                },
                'count': data['count'],
                'created_at': latest_status.created_at.isoformat(),
                'viewed': latest_status.id in viewed_status_ids
            })
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/status/<int:status_id>')
@login_required
def get_status_api(status_id):
    """Get status details"""
    try:
        status = Status.query.get_or_404(status_id)
        
        if status.expires_at < datetime.utcnow():
            return jsonify({'error': 'Status has expired'}), 404
        
        user_statuses = Status.query.filter(
            Status.user_id == status.user_id,
            Status.expires_at > datetime.utcnow()
        ).order_by(Status.created_at.desc()).all()
        
        status_data = {
            'id': status.id,
            'user': {
                'id': status.user.id,
                'username': status.user.username,
                'profile_picture': status.user.profile_picture
            },
            'media_type': status.media_type,
            'media_url': status.media_url,
            'text': status.text,
            'background_color': status.background_color,
            'text_color': status.text_color,
            'font_size': status.font_size,
            'created_at': status.created_at.isoformat(),
            'expires_at': status.expires_at.isoformat(),
            'views_count': status.views_count,
            'user_statuses': [
                {
                    'id': s.id,
                    'media_type': s.media_type,
                    'created_at': s.created_at.isoformat()
                }
                for s in user_statuses
            ]
        }
        
        return jsonify(status_data)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/status/viewed/<int:status_id>', methods=['POST'])
@login_required
def mark_status_viewed_api(status_id):
    """Mark a status as viewed"""
    try:
        status = Status.query.get_or_404(status_id)
        
        if status.expires_at < datetime.utcnow():
            return jsonify({'error': 'Status has expired'}), 404
        
        existing_view = StatusView.query.filter_by(
            user_id=current_user.id,
            status_id=status_id
        ).first()
        
        if not existing_view:
            view = StatusView(user_id=current_user.id, status_id=status_id)
            status.views_count += 1
            db.session.add(view)
            db.session.commit()
        
        return jsonify({'success': True, 'views_count': status.views_count})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/reel/<int:reel_id>')
@login_required
def get_reel_api(reel_id):
    """Get reel details"""
    try:
        reel = Reel.query.get_or_404(reel_id)
        
        if not current_user.can_interact_with(reel.user):
            return jsonify({'error': 'Cannot view this reel'}), 403
        
        is_liked = ReelLike.query.filter_by(
            user_id=current_user.id,
            reel_id=reel_id
        ).first() is not None
        
        reel_data = {
            'id': reel.id,
            'user': {
                'id': reel.user.id,
                'username': reel.user.username,
                'profile_picture': reel.user.profile_picture
            },
            'video_url': reel.video_url,
            'thumbnail_url': reel.thumbnail_url,
            'caption': reel.caption,
            'duration': reel.duration,
            'music': reel.music,
            'location': reel.location,
            'views_count': reel.views_count,
            'likes_count': reel.likes_count,
            'comments_count': reel.comments_count,
            'shares_count': reel.shares_count,
            'created_at': reel.created_at.isoformat(),
            'liked': is_liked
        }
        
        return jsonify(reel_data)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reel/<int:reel_id>/viewed', methods=['POST'])
@login_required
def mark_reel_viewed_api(reel_id):
    """Mark a reel as viewed"""
    try:
        reel = Reel.query.get_or_404(reel_id)
        
        existing_view = ReelView.query.filter_by(
            user_id=current_user.id,
            reel_id=reel_id
        ).first()
        
        if not existing_view:
            view = ReelView(user_id=current_user.id, reel_id=reel_id)
            reel.views_count += 1
            db.session.add(view)
            db.session.commit()
        
        return jsonify({'success': True, 'views_count': reel.views_count})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/reel/<int:reel_id>/comments')
@login_required
def get_reel_comments(reel_id):
    """Get comments for a reel"""
    try:
        reel = Reel.query.get_or_404(reel_id)
        
        comments = ReelComment.query.filter_by(
            reel_id=reel_id,
            is_deleted=False
        ).order_by(ReelComment.created_at.desc()).all()
        
        comments_data = []
        for comment in comments:
            comments_data.append({
                'id': comment.id,
                'content': comment.content,
                'created_at': comment.created_at.isoformat(),
                'user': {
                    'id': comment.author.id,
                    'username': comment.author.username,
                    'profile_picture': comment.author.profile_picture
                }
            })
        
        return jsonify({'comments': comments_data})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ UPDATED FEED ROUTE ============
@app.route('/feed')
@login_required
def feed():
    page = request.args.get('page', 1, type=int)
    
    followed_users = current_user.followed.all()
    followed_ids = [u.id for u in followed_users] + [current_user.id]
    
    blocked_ids = [b.id for b in current_user.blocked.all()]
    blocked_by_ids = [b.id for b in current_user.blocked_by.all()]
    
    posts_query = Post.query.filter(
        Post.user_id.in_(followed_ids),
        Post.is_deleted == False,
        ~Post.user_id.in_(blocked_ids),
        ~Post.user_id.in_(blocked_by_ids)
    ).order_by(Post.created_at.desc())
    
    posts = posts_query.paginate(page=page, per_page=20, error_out=False)
    
    trending = Hashtag.query.order_by(Hashtag.count.desc(), Hashtag.last_used.desc()).limit(5).all()
    
    suggestions = User.query.filter(
        User.id != current_user.id,
        ~User.id.in_(followed_ids),
        ~User.id.in_(blocked_ids),
        ~User.id.in_(blocked_by_ids)
    ).order_by(func.random()).limit(5).all()
    
    # Get status stories for feed
    status_stories = get_status_stories_for_feed(current_user)
    
    # Calculate total active statuses count
    total_active_statuses = 0
    for story in status_stories:
        total_active_statuses += story['count']
    
    # Check if we should show something special
    show_special_status_section = total_active_statuses > 5
    
    return render_template('feed.html', 
                         posts=posts, 
                         trending=trending, 
                         suggestions=suggestions,
                         status_stories=status_stories,
                         total_active_statuses=total_active_statuses,
                         show_special_status_section=show_special_status_section)
    
def get_status_stories_for_feed(current_user):
    """Helper function to get status stories"""
    if not current_user or not current_user.is_authenticated:
        return []
    
    followed_users = current_user.followed.all()
    followed_ids = [u.id for u in followed_users] + [current_user.id]
    
    users_with_status = []
    for user_id in followed_ids:
        user = User.query.get(user_id)
        if not user:
            continue
            
        active_statuses = Status.query.filter(
            Status.user_id == user_id,
            Status.expires_at > datetime.utcnow()
        ).order_by(Status.created_at.desc()).all()
        
        if active_statuses:
            viewed_status_ids = [sv.status_id for sv in 
                               StatusView.query.filter_by(user_id=current_user.id).all()]
            
            users_with_status.append({
                'user': user,
                'statuses': active_statuses,
                'has_unviewed': any(s.id not in viewed_status_ids for s in active_statuses),
                'count': len(active_statuses)
            })
    
    return users_with_status

# ============ TEMPLATE FILTERS ============
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



@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', user=current_user)

# Update account info
@app.route('/settings/account', methods=['POST'])
@login_required
def update_account():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip().lower()
    bio = request.form.get('bio', '').strip()
    
    # Validate username
    if username != current_user.username:
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return redirect(url_for('settings'))
        current_user.username = username
    
    # Validate email
    if email != current_user.email:
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('settings'))
        current_user.email = email
    
    current_user.bio = bio
    
    # Profile picture upload
    if 'profile_picture' in request.files:
        file = request.files['profile_picture']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(f"profile_{current_user.id}_{secrets.token_hex(8)}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', filename))
            current_user.profile_picture = filename
    
    # Cover picture upload
    if 'cover_picture' in request.files:
        file = request.files['cover_picture']
        if file and file.filename != '' and allowed_file(file.filename):
            filename = secure_filename(f"cover_{current_user.id}_{secrets.token_hex(8)}_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'covers', filename))
            current_user.cover_picture = filename
    
    db.session.commit()
    flash('Account settings updated.', 'success')
    return redirect(url_for('settings'))

# Update privacy
@app.route('/settings/privacy', methods=['POST'])
@login_required
def update_privacy():
    current_user.is_private = request.form.get('is_private') == 'on'
    current_user.allow_messages_from = request.form.get('allow_messages_from', 'everyone')
    current_user.allow_tagging = request.form.get('allow_tagging') == 'on'
    current_user.show_activity_status = request.form.get('show_activity_status') == 'on'
    db.session.commit()
    flash('Privacy settings updated.', 'success')
    return redirect(url_for('settings'))

# Update notifications
@app.route('/settings/notifications', methods=['POST'])
@login_required
def update_notifications():
    current_user.notify_likes = request.form.get('notify_likes') == 'on'
    current_user.notify_comments = request.form.get('notify_comments') == 'on'
    current_user.notify_follows = request.form.get('notify_follows') == 'on'
    current_user.notify_messages = request.form.get('notify_messages') == 'on'
    current_user.notify_mentions = request.form.get('notify_mentions') == 'on'
    current_user.email_notifications = request.form.get('email_notifications') == 'on'
    db.session.commit()
    flash('Notification settings updated.', 'success')
    return redirect(url_for('settings'))

# Update content & display
@app.route('/settings/content', methods=['POST'])
@login_required
def update_content():
    current_user.theme = request.form.get('theme', 'dark')
    current_user.language = request.form.get('language', 'en')
    current_user.autoplay_videos = request.form.get('autoplay_videos') == 'on'
    current_user.media_quality = request.form.get('media_quality', 'auto')
    db.session.commit()
    flash('Display settings updated.', 'success')
    return redirect(url_for('settings'))

# Security: change password
@app.route('/settings/security', methods=['POST'])
@login_required
def update_security():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('settings'))
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('settings'))
    
    password_error = validate_password(new_password)
    if password_error:
        flash(password_error, 'danger')
        return redirect(url_for('settings'))
    
    current_user.set_password(new_password)
    current_user.last_password_change = datetime.utcnow()
    db.session.commit()
    flash('Password changed successfully.', 'success')
    return redirect(url_for('settings'))

# Two-factor authentication placeholder
@app.route('/settings/2fa/enable', methods=['POST'])
@login_required
def enable_2fa():
    flash('Two-factor authentication will be available soon.', 'info')
    return redirect(url_for('settings'))

# Data & storage
@app.route('/settings/data/download', methods=['POST'])
@login_required
def download_data():
    flash('Your data export is being prepared. You will receive an email shortly.', 'info')
    return redirect(url_for('settings'))

@app.route('/settings/data/clear_cache', methods=['POST'])
@login_required
def clear_cache():
    flash('Cache cleared.', 'success')
    return redirect(url_for('settings'))

@app.route('/settings/blocked')
@login_required
def view_blocked_users():
    blocked = current_user.blocked.all()
    return render_template('blocked.html', blocked=blocked)

@app.route('/settings/unblock/<int:user_id>', methods=['POST'])
@login_required
def unblock_from_settings(user_id):
    user = User.query.get_or_404(user_id)
    current_user.unblock(user)
    db.session.commit()
    flash(f'Unblocked {user.username}.', 'success')
    return redirect(url_for('blocked_users'))

# Deactivate account
@app.route('/settings/deactivate', methods=['POST'])
@login_required
def deactivate_account():
    flash('Account deactivation is not yet implemented.', 'warning')
    return redirect(url_for('settings'))

# Delete account
@app.route('/settings/delete', methods=['POST'])
@login_required
def delete_account():
    password = request.form.get('password')
    if not current_user.check_password(password):
        flash('Incorrect password.', 'danger')
        return redirect(url_for('settings'))
    
    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    flash('Your account has been permanently deleted.', 'info')
    return redirect(url_for('index'))


#add vcf file 

def extract_emails_from_vcard(file_stream):
    """Extract unique email addresses from a vCard (.vcf) file."""
    emails = set()
    try:
        content = file_stream.read().decode('utf-8')
        vcards = vobject.readComponents(content)
        for vcard in vcards:
            if hasattr(vcard, 'email'):
                email_attr = vcard.email
                if isinstance(email_attr, list):
                    for e in email_attr:
                        emails.add(e.value)
                else:
                    emails.add(email_attr.value)
    except Exception as e:
        app.logger.error(f"vCard parsing error: {e}")
    return list(emails)

@app.route('/friends/import')
@login_required
def import_contacts():
    """Page to upload contacts."""
    return render_template('import_contacts.html')

@app.route('/friends/upload-contacts', methods=['POST'])
@login_required
def upload_contacts():
    """Process uploaded vCard and suggest friends."""
    if 'contacts_file' not in request.files:
        flash('No file uploaded.', 'danger')
        return redirect(url_for('import_contacts'))

    file = request.files['contacts_file']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('import_contacts'))

    if not file.filename.endswith('.vcf'):
        flash('Please upload a valid vCard (.vcf) file.', 'danger')
        return redirect(url_for('import_contacts'))

    # Parse emails
    emails = extract_emails_from_vcard(file)
    if not emails:
        flash('No email addresses found in the file.', 'warning')
        return redirect(url_for('import_contacts'))

    # Find users with those emails
    matched_users = User.query.filter(User.email.in_(emails)).all()

    # Exclude self and already followed users
    followed_ids = [u.id for u in current_user.followed.all()]
    suggestions = [
        u for u in matched_users
        if u.id != current_user.id and u.id not in followed_ids
    ]

    return render_template('contact_suggestions.html', suggestions=suggestions, method='vcard')

@app.route('/friends/follow-multiple', methods=['POST'])
@login_required
def follow_multiple():
    """Follow multiple users at once."""
    user_ids = request.form.getlist('user_ids')
    followed_count = 0
    for uid in user_ids:
        user = User.query.get(uid)
        if user and not current_user.is_following(user) and current_user.can_interact_with(user):
            current_user.follow(user)
            # Create notification
            notif = Notification(
                user_id=user.id,
                content=f"{current_user.username} started following you (via contacts)",
                link=f"/profile/{current_user.username}",
                notification_type='follow'
            )
            db.session.add(notif)
            followed_count += 1
    db.session.commit()
    flash(f'Followed {followed_count} user(s) from your contacts.', 'success')
    return redirect(url_for('feed'))

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
            email='admin@twit.com', 
            is_admin=True,
            is_verified=True
        )
        admin.set_password('Admin123!')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)