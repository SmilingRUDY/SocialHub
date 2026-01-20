from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///social_media.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.String(500), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    followers = db.relationship('Follow', foreign_keys='Follow.following_id', backref='user', lazy=True,
                                cascade='all, delete-orphan')
    following = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower_user', lazy=True,
                                cascade='all, delete-orphan')


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255), default=None)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    likes = db.relationship('Like', backref='post', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    user = db.relationship('User', backref='comments')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')


@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    following_ids = [f.following_id for f in user.following]
    following_ids.append(user.id)

    posts = Post.query.filter(Post.user_id.in_(following_ids)).order_by(Post.created_at.desc()).all()
    return render_template('feed.html', posts=posts, user=user)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            return 'Username already exists', 400

        user = User(username=username, email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        return redirect(url_for('index'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))

        return 'Invalid credentials', 400

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    current_user = User.query.get(session.get('user_id'))
    is_following = False

    if current_user and current_user.id != user.id:
        is_following = Follow.query.filter_by(follower_id=current_user.id, following_id=user.id).first() is not None

    posts = Post.query.filter_by(user_id=user.id).order_by(Post.created_at.desc()).all()
    return render_template('profile.html', user=user, posts=posts, is_following=is_following, current_user=current_user)


@app.route('/post', methods=['POST'])
def create_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    content = request.form.get('content')
    image = None

    if 'image' in request.files:
        file = request.files['image']
        if file and file.filename:
            filename = secure_filename(f"{session['user_id']}_{datetime.utcnow().timestamp()}_{file.filename}")
            os.makedirs('static/uploads', exist_ok=True)
            file.save(os.path.join('static/uploads', filename))
            image = filename

    if content or image:
        post = Post(content=content, user_id=session['user_id'], image=image)
        db.session.add(post)
        db.session.commit()

    return redirect(url_for('index'))


@app.route('/post/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != session.get('user_id'):
        return 'Unauthorized', 403

    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/post/<int:post_id>/like', methods=['POST'])
def like_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    existing = Like.query.filter_by(user_id=session['user_id'], post_id=post_id).first()
    if existing:
        db.session.delete(existing)
    else:
        like = Like(user_id=session['user_id'], post_id=post_id)
        db.session.add(like)

    db.session.commit()
    return redirect(request.referrer or url_for('index'))


@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    content = request.form.get('content')
    if content:
        comment = Comment(content=content, user_id=session['user_id'], post_id=post_id)
        db.session.add(comment)
        db.session.commit()

    return redirect(request.referrer or url_for('index'))


@app.route('/follow/<int:user_id>', methods=['POST'])
def follow_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session['user_id'] == user_id:
        return 'Cannot follow yourself', 400

    existing = Follow.query.filter_by(follower_id=session['user_id'], following_id=user_id).first()
    if existing:
        db.session.delete(existing)
    else:
        follow = Follow(follower_id=session['user_id'], following_id=user_id)
        db.session.add(follow)

    db.session.commit()
    return redirect(request.referrer or url_for('index'))


@app.route('/messages')
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    conversations = db.session.query(Message).filter(
        (Message.sender_id == user.id) | (Message.receiver_id == user.id)
    ).order_by(Message.created_at.desc()).all()

    unique_users = {}
    for msg in conversations:
        other_id = msg.receiver_id if msg.sender_id == user.id else msg.sender_id
        if other_id not in unique_users:
            unique_users[other_id] = {'user': User.query.get(other_id), 'unread': 0, 'last_msg': msg}
        if msg.receiver_id == user.id and not msg.is_read:
            unique_users[other_id]['unread'] += 1

    conversation_users = list(unique_users.values())
    return render_template('messages.html', user=user, conversation_users=conversation_users)


@app.route('/chat/<int:user_id>')
def chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    other_user = User.query.get_or_404(user_id)

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == other_user.id)) |
        ((Message.sender_id == other_user.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.created_at.asc()).all()

    Message.query.filter(Message.receiver_id == current_user.id, Message.sender_id == other_user.id).update(
        {'is_read': True})
    db.session.commit()

    return render_template('chat.html', current_user=current_user, other_user=other_user, messages=messages)


@app.route('/send-message/<int:receiver_id>', methods=['POST'])
def send_message(receiver_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    content = request.form.get('content')
    if content:
        message = Message(sender_id=session['user_id'], receiver_id=receiver_id, content=content)
        db.session.add(message)
        db.session.commit()

    return redirect(url_for('chat', user_id=receiver_id))


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)