from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from itsdangerous import Serializer
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, IntegerField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
import time
from PIL import Image
import secrets
from dateutil import tz
import pytz
import uuid
from functools import wraps
from flask_migrate import Migrate
from enum import Enum
import sys

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Bu sayfayı görüntülemek için lütfen giriş yapın.'
login_manager.login_message_category = 'info'

# Veritabanı klasörünü oluştur
if not os.path.exists('instance'):
    os.makedirs('instance')

class UserRole(str, Enum):
    ADMIN = 'admin'
    EDITOR = 'editor'
    AUTHOR = 'author'
    TRANSLATOR = 'translator'
    USER = 'user'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.utc))
    last_login = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.utc))
    bio = db.Column(db.Text)
    location = db.Column(db.String(100))
    social_media = db.Column(db.String(120))
    total_views = db.Column(db.Integer, default=0)
    total_likes = db.Column(db.Integer, default=0)
    is_admin = db.Column(db.Boolean, default=False)
    is_editor = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default=UserRole.USER.value)
    is_active = db.Column(db.Boolean, default=True)
    stories = db.relationship('Story', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    collaborations = db.relationship('StoryCollaborator', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

    def has_role(self, role):
        """Kullanıcının belirli bir role sahip olup olmadığını kontrol et"""
        if isinstance(role, str):
            return self.role == role
        return self.role == role.value

    def has_permission(self, permission):
        """Kullanıcının belirli bir izne sahip olup olmadığını kontrol et"""
        if self.is_admin:
            return True
            
        role_permissions = {
            UserRole.ADMIN: ['admin_panel', 'manage_users', 'manage_stories', 'manage_comments', 
                           'write_story', 'edit_story', 'delete_story', 'add_chapter', 
                           'edit_chapter', 'delete_chapter', 'translate_story'],
            UserRole.EDITOR: ['manage_stories', 'edit_story', 'manage_comments', 
                            'write_story', 'add_chapter', 'edit_chapter'],
            UserRole.AUTHOR: ['write_story', 'edit_story', 'add_chapter', 'edit_chapter'],
            UserRole.TRANSLATOR: ['translate_story'],
            UserRole.USER: ['write_story']
        }
        
        return permission in role_permissions.get(UserRole(self.role), [])

    def can_edit_story(self, story):
        """Kullanıcının hikayeyi düzenleyebilme yetkisini kontrol et"""
        if self.is_admin:
            return True
        if story.author_id == self.id:
            return True
        collab = StoryCollaborator.query.filter_by(
            user_id=self.id, 
            story_id=story.id
        ).first()
        return collab and collab.can_edit

    def can_add_chapter(self, story):
        """Kullanıcının hikayeye bölüm ekleyebilme yetkisini kontrol et"""
        if self.is_admin:
            return True
        if story.author_id == self.id:
            return True
        collab = StoryCollaborator.query.filter_by(
            user_id=self.id, 
            story_id=story.id
        ).first()
        return collab and collab.can_add_chapter

    def can_translate(self, story):
        """Kullanıcının hikayeyi çevirebilme yetkisini kontrol et"""
        if self.is_admin:
            return True
        collab = StoryCollaborator.query.filter_by(
            user_id=self.id, 
            story_id=story.id,
            role='translator'
        ).first()
        return collab and collab.can_translate

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.utc))
    content = db.Column(db.Text, nullable=False)
    summary = db.Column(db.String(500), nullable=False)
    cover_image = db.Column(db.String(20), nullable=False, default='default.jpg')
    category = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chapters = db.relationship('Chapter', backref='story', lazy=True)
    comments = db.relationship('Comment', backref='story', lazy=True)
    likes = db.relationship('Like', backref='story', lazy=True)
    collaborators = db.relationship('StoryCollaborator', backref='story', lazy=True)
    status = db.Column(db.String(20), default='ongoing')  # ongoing, completed, hiatus
    views = db.Column(db.Integer, default=0)
    featured = db.Column(db.Boolean, default=False)  # Öne çıkan hikaye mi?
    featured_date = db.Column(db.DateTime, nullable=True)  # Öne çıkarma tarihi
    featured_type = db.Column(db.String(20), nullable=True)  # daily, weekly, monthly
    editor_pick = db.Column(db.Boolean, default=False)  # Editör seçimi mi?
    award = db.Column(db.String(50), nullable=True)  # Kazanan ödülü (varsa)
    original_language = db.Column(db.String(5), default='tr')  # Orijinal dil
    is_translation = db.Column(db.Boolean, default=False)  # Çeviri mi?
    original_story_id = db.Column(db.Integer, db.ForeignKey('story.id', name='fk_original_story'), nullable=True)  # Orijinal hikaye ID

class Chapter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    chapter_number = db.Column(db.Integer, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.utc))
    views = db.Column(db.Integer, default=0)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    comments = db.relationship('ChapterComment', backref='chapter', lazy=True, cascade='all, delete-orphan')

class StoryCollaborator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # author, editor, translator
    date_added = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.utc))
    can_edit = db.Column(db.Boolean, default=False)
    can_add_chapter = db.Column(db.Boolean, default=False)
    can_translate = db.Column(db.Boolean, default=False)
    language = db.Column(db.String(5), nullable=True)  # Çeviri dili (örn: 'en', 'tr')

class ChapterComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    date_liked = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.utc))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)

class LoginForm(FlaskForm):
    email = StringField('E-posta', validators=[
        DataRequired(message='E-posta adresi gerekli'),
        Email(message='Geçerli bir e-posta adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(message='Şifre gerekli'),
        Length(min=6, message='Şifre en az 6 karakter olmalı')
    ])
    remember = BooleanField('Beni Hatırla')
    submit = SubmitField('Giriş Yap')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if not user:
            raise ValidationError('Bu e-posta adresi ile kayıtlı hesap bulunamadı.')
        if not user.is_active:
            raise ValidationError('Bu hesap devre dışı bırakılmış. Lütfen yönetici ile iletişime geçin.')

class RegistrationForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[
        DataRequired(message='Kullanıcı adı gerekli'),
        Length(min=3, max=20, message='Kullanıcı adı 3-20 karakter arasında olmalı')
    ])
    email = StringField('E-posta', validators=[
        DataRequired(message='E-posta adresi gerekli'),
        Email(message='Geçerli bir e-posta adresi girin')
    ])
    password = PasswordField('Şifre', validators=[
        DataRequired(message='Şifre gerekli'),
        Length(min=6, message='Şifre en az 6 karakter olmalı')
    ])
    confirm_password = PasswordField('Şifre (Tekrar)', validators=[
        DataRequired(message='Şifreyi tekrar girin'),
        EqualTo('password', message='Şifreler eşleşmiyor')
    ])
    submit = SubmitField('Kayıt Ol')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data.lower()).first()
        if user:
            raise ValidationError('Bu kullanıcı adı zaten alınmış. Lütfen başka bir kullanıcı adı seçin.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data.lower()).first()
        if user:
            raise ValidationError('Bu e-posta adresi zaten kayıtlı. Lütfen başka bir e-posta adresi kullanın.')

class StoryForm(FlaskForm):
    title = StringField('Hikaye Başlığı', validators=[
        DataRequired(message='Başlık gereklidir'),
        Length(min=2, max=100, message='Başlık 2-100 karakter arasında olmalıdır')
    ])
    category = SelectField('Kategori', choices=[
        ('Fantastik', 'Fantastik'),
        ('Bilim Kurgu', 'Bilim Kurgu'),
        ('Romantik', 'Romantik'),
        ('Macera', 'Macera'),
        ('Gizem', 'Gizem'),
        ('Korku', 'Korku'),
        ('Dram', 'Dram'),
        ('Diğer', 'Diğer')
    ], validators=[DataRequired(message='Kategori seçimi gereklidir')])
    summary = TextAreaField('Kısa Özet', validators=[
        DataRequired(message='Özet gereklidir'),
        Length(min=10, max=500, message='Özet 10-500 karakter arasında olmalıdır')
    ])
    cover_image = FileField('Kapak Resmi', validators=[
        FileAllowed(['jpg', 'jpeg', 'png'], 'Sadece JPG, JPEG ve PNG dosyaları yüklenebilir')
    ])
    submit = SubmitField('Hikaye Oluştur')

class ChapterForm(FlaskForm):
    title = StringField('Bölüm Başlığı', validators=[
        DataRequired(message='Başlık gereklidir'),
        Length(min=2, max=100, message='Başlık 2-100 karakter arasında olmalıdır')
    ])
    content = TextAreaField('Bölüm İçeriği', validators=[
        DataRequired(message='İçerik gereklidir')
    ])
    submit = SubmitField('Bölümü Kaydet')

class CollaboratorForm(FlaskForm):
    username = StringField('Kullanıcı Adı', validators=[
        DataRequired(message='Kullanıcı adı gerekli'),
        Length(min=3, max=20, message='Kullanıcı adı 3-20 karakter arasında olmalı')
    ])
    role = SelectField('Rol', choices=[
        ('author', 'Ortak Yazar'),
        ('editor', 'Editör'),
        ('translator', 'Çevirmen')
    ], validators=[DataRequired(message='Rol seçimi gerekli')])
    language = SelectField('Çeviri Dili', choices=[
        ('', 'Dil Seçin'),
        ('en', 'İngilizce'),
        ('es', 'İspanyolca'),
        ('fr', 'Fransızca'),
        ('de', 'Almanca'),
        ('it', 'İtalyanca'),
        ('ru', 'Rusça'),
        ('ar', 'Arapça'),
        ('zh', 'Çince')
    ])
    permissions = SelectMultipleField('İzinler', choices=[
        ('can_edit', 'Düzenleme'),
        ('can_add_chapter', 'Bölüm Ekleme'),
        ('can_translate', 'Çeviri')
    ])
    submit = SubmitField('Ekle')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data.lower()).first()
        if not user:
            raise ValidationError('Bu kullanıcı adı bulunamadı.')
        if not user.is_active:
            raise ValidationError('Bu kullanıcı hesabı aktif değil.')

    def validate_language(self, language):
        if self.role.data == 'translator' and not language.data:
            raise ValidationError('Çevirmen için dil seçimi zorunludur.')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    stories = Story.query.order_by(Story.date_posted.desc()).all()
    categories = ['Macera', 'Romantik', 'Bilim Kurgu', 'Fantastik', 'Gizem', 'Korku', 'Dram', 'Komedi', 'Diğer']
    
    # Öne çıkan hikayeler (günlük/haftalık/aylık)
    now = datetime.now(pytz.utc)
    daily_cutoff = now - timedelta(days=1)
    weekly_cutoff = now - timedelta(days=7)
    monthly_cutoff = now - timedelta(days=30)
    
    # Günlük popüler hikayeler (görüntülenme + beğeni sayısı)
    daily_popular = Story.query.filter(Story.date_posted >= daily_cutoff)\
        .order_by((Story.views + db.func.count(Like.id)).desc())\
        .outerjoin(Like).group_by(Story.id).limit(5).all()
    
    # Haftalık popüler hikayeler
    weekly_popular = Story.query.filter(Story.date_posted >= weekly_cutoff)\
        .order_by((Story.views + db.func.count(Like.id)).desc())\
        .outerjoin(Like).group_by(Story.id).limit(5).all()
    
    # Aylık popüler hikayeler
    monthly_popular = Story.query.filter(Story.date_posted >= monthly_cutoff)\
        .order_by((Story.views + db.func.count(Like.id)).desc())\
        .outerjoin(Like).group_by(Story.id).limit(5).all()
    
    # Editör seçimleri (en fazla 10 adet gösterilecek)
    editor_picks = Story.query.filter_by(editor_pick=True).order_by(Story.featured_date.desc()).limit(10).all()
    
    # Kazananlar (ödül alanlar)
    winners = Story.query.filter(Story.award != None).order_by(Story.featured_date.desc()).limit(10).all()
    
    return render_template('home.html', 
                          stories=stories, 
                          categories=categories,
                          daily_popular=daily_popular,
                          weekly_popular=weekly_popular,
                          monthly_popular=monthly_popular,
                          editor_picks=editor_picks,
                          winners=winners)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data.lower()).first()
            
            if not user:
                flash('Bu e-posta adresi ile kayıtlı hesap bulunamadı.', 'danger')
                return render_template('login.html', title='Giriş Yap', form=form)
            
            if not user.is_active:
                flash('Hesabınız devre dışı bırakılmış. Lütfen yönetici ile iletişime geçin.', 'danger')
                return render_template('login.html', title='Giriş Yap', form=form)
            
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                user.last_login = datetime.now(pytz.utc)
                db.session.commit()
                
                # Log the successful login
                print(f"Successful login - User: {user.username}, Role: {user.role}, Time: {user.last_login}")
                
                next_page = request.args.get('next')
                flash(f'Hoş geldiniz, {user.username}!', 'success')
                
                # Role-specific redirects
                if user.is_admin and not next_page:
                    return redirect(url_for('admin_dashboard'))
                elif user.has_role(UserRole.EDITOR) and not next_page:
                    return redirect(url_for('admin_stories'))
                
                return redirect(next_page) if next_page else redirect(url_for('home'))
            else:
                flash('Giriş başarısız. Lütfen şifrenizi kontrol edin.', 'danger')
        except Exception as e:
            print(f"Login error: {str(e)}")  # Log the error
            flash('Giriş sırasında bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
            db.session.rollback()
    
    return render_template('login.html', title='Giriş Yap', form=form)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(
                username=form.username.data.lower(),
                email=form.email.data.lower(),
                password=hashed_password,
                role=UserRole.USER.value,
                is_active=True
            )
            db.session.add(user)
            db.session.commit()
            flash('Hesabınız başarıyla oluşturuldu! Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Kayıt sırasında bir hata oluştu. Lütfen tekrar deneyin.', 'danger')
    return render_template('register.html', title='Kayıt Ol', form=form)

@app.route("/logout")
@login_required
def logout():
    if current_user.is_authenticated:
        # Log the logout
        print(f"User logged out - Username: {current_user.username}, Time: {datetime.now(pytz.utc)}")
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('home'))

def save_picture(form_picture, folder):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext.lower()
    
    # Klasörü oluştur
    picture_path = os.path.join(app.root_path, 'static', folder)
    os.makedirs(picture_path, exist_ok=True)
    
    # Resmi kaydet
    picture_path = os.path.join(picture_path, picture_fn)
    
    # Resmi yeniden boyutlandır
    output_size = (800, 450)
    i = Image.open(form_picture)
    i = i.convert('RGB')  # JPEG desteği için
    i.thumbnail(output_size, Image.Resampling.LANCZOS)
    i.save(picture_path)
    
    return picture_fn

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Bu sayfayı görüntülemek için giriş yapmalısınız.', 'warning')
                return redirect(url_for('login', next=request.url))
            if not current_user.has_permission(permission):
                flash('Bu işlem için yetkiniz bulunmuyor.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Bu sayfayı görüntülemek için giriş yapmalısınız.', 'warning')
                return redirect(url_for('login', next=request.url))
            if not current_user.has_role(role):
                flash('Bu işlem için gerekli role sahip değilsiniz.', 'danger')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Bu sayfaya erişim yetkiniz yok.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/write', methods=['GET', 'POST'])
@login_required
@permission_required('write_story')
def write_story():
    form = StoryForm()
    if form.validate_on_submit():
        story = Story(
            title=form.title.data,
            category=form.category.data,
            summary=form.summary.data,
            content='',
            author=current_user
        )
        
        if form.cover_image.data:
            picture_file = save_picture(form.cover_image.data, 'story_covers')
            story.cover_image = picture_file
        
        db.session.add(story)
        db.session.commit()
        
        flash('Hikayeniz başarıyla oluşturuldu! Şimdi bölüm ekleyebilirsiniz.', 'success')
        return redirect(url_for('add_chapter', story_id=story.id))
    
    return render_template('write.html', title='Yeni Hikaye', form=form)

@app.route("/story/<int:story_id>/chapter/new", methods=['GET', 'POST'])
@login_required
@permission_required('add_chapter')
def add_chapter(story_id):
    story = Story.query.get_or_404(story_id)
    if not current_user.can_add_chapter(story):
        abort(403)
    
    form = ChapterForm()
    if form.validate_on_submit():
        next_chapter = len(story.chapters) + 1
        
        chapter = Chapter(
            title=form.title.data,
            content=form.content.data,
            chapter_number=next_chapter,
            story=story
        )
        
        db.session.add(chapter)
        db.session.commit()
        
        flash('Bölüm başarıyla eklendi!', 'success')
        return redirect(url_for('story', story_id=story.id))
    
    return render_template('add_chapter.html', title='Yeni Bölüm',
                         form=form, story=story)

@app.route("/story/<int:story_id>")
def story(story_id):
    story = Story.query.get_or_404(story_id)
    return render_template('story.html', title=story.title, story=story)

@app.route("/story/<int:story_id>/update", methods=['GET', 'POST'])
@login_required
def update_story(story_id):
    story = Story.query.get_or_404(story_id)
    if story.author != current_user:
        abort(403)
    form = StoryForm()
    if form.validate_on_submit():
        story.title = form.title.data
        story.content = form.content.data
        story.summary = form.summary.data
        story.cover_image = form.cover_image.data
        story.category = form.category.data
        db.session.commit()
        flash('Hikayeniz başarıyla güncellendi!', 'success')
        return redirect(url_for('story', story_id=story.id))
    elif request.method == 'GET':
        form.title.data = story.title
        form.content.data = story.content
        form.summary.data = story.summary
        form.cover_image.data = story.cover_image
        form.category.data = story.category
    return render_template('write.html', title='Hikayeyi Düzenle', 
                         form=form, legend='Hikayeyi Düzenle')

@app.route("/story/<int:story_id>/delete", methods=['POST'])
@login_required
def delete_story(story_id):
    story = Story.query.get_or_404(story_id)
    if story.author != current_user:
        abort(403)
    db.session.delete(story)
    db.session.commit()
    flash('Hikayeniz silindi!', 'success')
    return redirect(url_for('home'))

@app.route('/profile/<string:username>')
def profile(username):
    user = User.query.filter_by(username=username.lower()).first_or_404()
    stories = Story.query.filter_by(author=user)\
        .order_by(Story.date_posted.desc())\
        .all()
    return render_template('profile.html', user=user, stories=stories)

@app.route('/like/<int:story_id>', methods=['POST'])
@login_required
def like_story(story_id):
    story = Story.query.get_or_404(story_id)
    
    # Kullanıcının daha önce beğenip beğenmediğini kontrol et
    like = Like.query.filter_by(user_id=current_user.id, story_id=story_id).first()
    
    if like:
        # Beğeniyi kaldır
        db.session.delete(like)
        db.session.commit()
        return jsonify({'status': 'unliked', 'likes': len(story.likes)})
    else:
        # Beğeni ekle
        like = Like(user_id=current_user.id, story_id=story_id)
        db.session.add(like)
        db.session.commit()
        return jsonify({'status': 'liked', 'likes': len(story.likes)})

@app.route('/comment/<int:story_id>', methods=['POST'])
@login_required
def comment(story_id):
    content = request.form.get('content')
    comment = Comment(content=content, user_id=current_user.id, story_id=story_id)
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('story', story_id=story_id))

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user:
        abort(403)
    db.session.delete(comment)
    db.session.commit()
    return '', 204

@app.route('/search')
def search():
    query = request.args.get('q', '')
    stories = Story.query.filter(
        db.or_(
            Story.title.ilike(f'%{query}%'),
            Story.content.ilike(f'%{query}%'),
            Story.category.ilike(f'%{query}%')
        )
    ).order_by(Story.date_posted.desc()).all()
    return render_template('search.html', stories=stories, query=query)

@app.route("/settings")
@login_required
def settings():
    return render_template('settings.html')

@app.route("/update_profile", methods=['POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        
        if username != current_user.username:
            user = User.query.filter_by(username=username).first()
            if user:
                flash('Bu kullanıcı adı zaten alınmış.', 'danger')
                return redirect(url_for('settings'))
        
        if email != current_user.email:
            user = User.query.filter_by(email=email).first()
            if user:
                flash('Bu e-posta adresi zaten kullanılıyor.', 'danger')
                return redirect(url_for('settings'))
        
        current_user.username = username
        current_user.email = email
        db.session.commit()
        flash('Profil bilgileriniz güncellendi!', 'success')
        return redirect(url_for('settings'))

@app.route("/change_password", methods=['POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not bcrypt.check_password_hash(current_user.password, current_password):
            flash('Mevcut şifreniz yanlış.', 'danger')
            return redirect(url_for('settings'))
        
        if new_password != confirm_password:
            flash('Yeni şifreler eşleşmiyor.', 'danger')
            return redirect(url_for('settings'))
        
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password = hashed_password
        db.session.commit()
        flash('Şifreniz başarıyla değiştirildi!', 'success')
        return redirect(url_for('settings'))

@app.route("/update_notifications", methods=['POST'])
@login_required
def update_notifications():
    if request.method == 'POST':
        current_user.email_notifications = 'email_notifications' in request.form
        current_user.like_notifications = 'like_notifications' in request.form
        current_user.comment_notifications = 'comment_notifications' in request.form
        db.session.commit()
        flash('Bildirim ayarlarınız güncellendi!', 'success')
        return redirect(url_for('settings'))

@app.route("/update_photo", methods=['POST'])
@login_required
def update_photo():
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('Dosya seçilmedi.', 'danger')
            return redirect(url_for('settings'))
            
        photo = request.files['photo']
        if photo.filename == '':
            flash('Dosya seçilmedi.', 'danger')
            return redirect(url_for('settings'))
            
        if photo and allowed_file(photo.filename):
            # Eski fotoğrafı sil (default.jpg değilse)
            if current_user.image_file != 'default.jpg':
                old_photo_path = os.path.join(app.root_path, 'static/profile_pics', current_user.image_file)
                if os.path.exists(old_photo_path):
                    os.remove(old_photo_path)
            
            # Yeni fotoğrafı kaydet
            filename = secure_filename(photo.filename)
            file_ext = os.path.splitext(filename)[1]
            new_filename = f"user_{current_user.id}{file_ext}"
            photo.save(os.path.join(app.root_path, 'static/profile_pics', new_filename))
            
            # Fotoğrafı yeniden boyutlandır
            output_size = (150, 150)
            img = Image.open(os.path.join(app.root_path, 'static/profile_pics', new_filename))
            img.thumbnail(output_size)
            img.save(os.path.join(app.root_path, 'static/profile_pics', new_filename))
            
            current_user.image_file = new_filename
            db.session.commit()
            flash('Profil fotoğrafınız güncellendi!', 'success')
        else:
            flash('Lütfen geçerli bir resim dosyası seçin.', 'danger')
            
        return redirect(url_for('settings'))

@app.route("/delete_account", methods=['POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_delete = request.form.get('confirm_delete')
        
        if not bcrypt.check_password_hash(current_user.password, password):
            flash('Şifreniz yanlış.', 'danger')
            return redirect(url_for('settings'))
            
        if not confirm_delete:
            flash('Lütfen hesap silme işlemini onaylayın.', 'danger')
            return redirect(url_for('settings'))
            
        # Profil fotoğrafını sil
        if current_user.image_file != 'default.jpg':
            photo_path = os.path.join(app.root_path, 'static/profile_pics', current_user.image_file)
            if os.path.exists(photo_path):
                os.remove(photo_path)
        
        # Kullanıcıyı ve ilişkili verileri sil
        user = User.query.get(current_user.id)
        db.session.delete(user)
        db.session.commit()
        
        flash('Hesabınız başarıyla silindi.', 'info')
        return redirect(url_for('home'))

@app.route("/story/<int:story_id>/add_collaborator", methods=['GET', 'POST'])
@login_required
def add_collaborator(story_id):
    story = Story.query.get_or_404(story_id)
    if current_user != story.author and not current_user.is_admin:
        abort(403)
    
    form = CollaboratorForm()
    if form.validate_on_submit():
        collaborator = User.query.filter_by(username=form.username.data.lower()).first()
        
        if collaborator == current_user:
            flash('Kendinizi ortak yazar olarak ekleyemezsiniz.', 'danger')
            return redirect(url_for('add_collaborator', story_id=story_id))
            
        existing_collab = StoryCollaborator.query.filter_by(
            story_id=story.id, user_id=collaborator.id).first()
        if existing_collab:
            flash('Bu kullanıcı zaten ortak yazar.', 'warning')
            return redirect(url_for('add_collaborator', story_id=story_id))
        
        # İzinleri ayarla
        permissions = form.permissions.data
        can_edit = 'can_edit' in permissions
        can_add_chapter = 'can_add_chapter' in permissions
        can_translate = 'can_translate' in permissions
        
        # Rol bazlı varsayılan izinler
        if form.role.data == 'author':
            can_edit = True
            can_add_chapter = True
        elif form.role.data == 'editor':
            can_edit = True
        elif form.role.data == 'translator':
            can_translate = True
        
        collaboration = StoryCollaborator(
            user_id=collaborator.id,
            story_id=story.id,
            role=form.role.data,
            can_edit=can_edit,
            can_add_chapter=can_add_chapter,
            can_translate=can_translate,
            language=form.language.data if form.role.data == 'translator' else None
        )
        
        # Eğer çevirmen ise ve dil seçilmişse, yeni bir çeviri hikayesi oluştur
        if form.role.data == 'translator' and form.language.data:
            translated_story = Story(
                title=story.title,
                content=story.content,
                summary=story.summary,
                category=story.category,
                cover_image=story.cover_image,
                author=collaborator,
                is_translation=True,
                original_story_id=story.id,
                original_language=story.original_language
            )
            db.session.add(translated_story)
            
        db.session.add(collaboration)
        db.session.commit()
        
        role_display = {
            'author': 'ortak yazar',
            'editor': 'editör',
            'translator': 'çevirmen'
        }
        
        flash(f'{collaborator.username} {role_display[form.role.data]} olarak eklendi.', 'success')
        return redirect(url_for('story', story_id=story_id))
    
    return render_template('add_collaborator.html', title='Ortak Yazar Ekle', form=form, story=story)

@app.route("/profile/<string:username>/stats")
def user_stats(username):
    user = User.query.filter_by(username=username).first_or_404()
    stats = {
        'total_stories': len(user.stories),
        'total_views': user.total_views,
        'total_likes': user.total_likes,
        'total_comments': len(user.comments),
        'join_date': user.created_at,
        'collaborations': len(user.collaborations)
    }
    return render_template('user_stats.html', user=user, stats=stats)

@app.route('/story/<int:story_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_story(story_id):
    story = Story.query.get_or_404(story_id)
    if story.author != current_user:
        abort(403)
    form = StoryForm()
    if form.validate_on_submit():
        story.title = form.title.data
        story.category = form.category.data
        story.summary = form.summary.data
        
        if form.cover_image.data:
            if story.cover_image:  # Delete old cover image if it exists
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], story.cover_image)
                if os.path.exists(old_image_path):
                    os.remove(old_image_path)
            
            image = form.cover_image.data
            filename = secure_filename(f"{uuid.uuid4()}_{image.filename}")
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            story.cover_image = filename

        db.session.commit()
        flash('Hikayeniz başarıyla güncellendi!', 'success')
        return redirect(url_for('story', story_id=story.id))

    elif request.method == 'GET':
        form.title.data = story.title
        form.category.data = story.category
        form.summary.data = story.summary

    return render_template('write.html', form=form, title='Hikayeyi Düzenle', legend='Hikayeyi Düzenle')

# Yardım Merkezi Route'ları
@app.route('/faq')
def faq():
    return render_template('help/faq.html')

@app.route('/help')
def help_center():
    return render_template('help/help_center.html')

@app.route('/privacy')
def privacy():
    return render_template('help/privacy.html')

@app.route('/terms')
def terms():
    return render_template('help/terms.html')

@app.route('/contact')
def contact():
    return render_template('help/contact.html')

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Admin Panel Routes
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_stories = Story.query.count()
    total_likes = Like.query.count()
    total_comments = Comment.query.count()
    
    # Get recent users and stories
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_stories = Story.query.order_by(Story.date_posted.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                          total_users=total_users,
                          total_stories=total_stories,
                          total_likes=total_likes,
                          total_comments=total_comments,
                          recent_users=recent_users,
                          recent_stories=recent_stories)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.username).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>')
@login_required
@admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('admin/user_detail.html', user=user)

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_edit(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.is_admin = 'is_admin' in request.form
        user.is_editor = 'is_editor' in request.form
        
        if request.form.get('password'):
            user.password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        
        db.session.commit()
        flash(f'{user.username} kullanıcısı güncellendi.', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/user_edit.html', user=user)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_user_delete(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin and user.id == current_user.id:
        flash('Kendinizi silemezsiniz!', 'danger')
    else:
        db.session.delete(user)
        db.session.commit()
        flash(f'{user.username} kullanıcısı silindi.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/stories')
@login_required
@admin_required
def admin_stories():
    stories = Story.query.order_by(Story.date_posted.desc()).all()
    return render_template('admin/stories.html', stories=stories)

@app.route('/admin/story/<int:story_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_story_delete(story_id):
    story = Story.query.get_or_404(story_id)
    db.session.delete(story)
    db.session.commit()
    flash(f'"{story.title}" hikayesi silindi.', 'success')
    return redirect(url_for('admin_stories'))

@app.route('/admin/statistics')
@login_required
@admin_required
def admin_statistics():
    # Basic statistics
    total_users = User.query.count()
    total_stories = Story.query.count()
    total_chapters = Chapter.query.count()
    total_comments = Comment.query.count()
    total_likes = Like.query.count()
    
    # User activity
    active_users = User.query.order_by(User.last_login.desc()).limit(10).all()
    
    # Popular stories
    popular_stories = Story.query.order_by(Story.views.desc()).limit(10).all()
    
    # Get monthly user registrations for the past year
    now = datetime.now(pytz.utc)
    months = []
    monthly_registrations = []
    
    for i in range(12):
        # Calculate month and year (going backwards from current month)
        current_month = now.month
        current_year = now.year
        
        month = ((current_month - i - 1) % 12) + 1
        year = current_year - ((current_month - i - 1) // 12)
        
        # Create date objects for start and end of month
        start_date = datetime(year, month, 1, tzinfo=pytz.utc)
        
        if month == 12:
            end_date = datetime(year + 1, 1, 1, tzinfo=pytz.utc) - timedelta(seconds=1)
        else:
            end_date = datetime(year, month + 1, 1, tzinfo=pytz.utc) - timedelta(seconds=1)
        
        # Count users registered in that month
        count = User.query.filter(User.created_at >= start_date, User.created_at <= end_date).count()
        
        # Add to our data (in reverse order so oldest is first)
        months.insert(0, start_date.strftime('%B'))
        monthly_registrations.insert(0, count)
    
    # Get story categories distribution
    categories = ['Fantastik', 'Bilim Kurgu', 'Romantik', 'Macera', 'Gizem', 'Korku', 'Dram', 'Diğer']
    category_counts = []
    
    for category in categories:
        count = Story.query.filter_by(category=category).count()
        category_counts.append(count)
    
    # Get stories by status
    status_ongoing = Story.query.filter_by(status='ongoing').count()
    status_completed = Story.query.filter_by(status='completed').count()
    status_hiatus = Story.query.filter_by(status='hiatus').count()
    status_counts = [status_ongoing, status_completed, status_hiatus]
    
    return render_template('admin/statistics.html',
                          total_users=total_users,
                          total_stories=total_stories,
                          total_chapters=total_chapters,
                          total_comments=total_comments,
                          total_likes=total_likes,
                          active_users=active_users,
                          popular_stories=popular_stories,
                          months=months,
                          monthly_registrations=monthly_registrations,
                          categories=categories,
                          category_counts=category_counts,
                          status_counts=status_counts)

@app.route('/admin/story/<int:story_id>')
@login_required
@admin_required
def admin_story_detail(story_id):
    story = Story.query.get_or_404(story_id)
    return render_template('admin/story_detail.html', story=story)

@app.route('/admin/story/<int:story_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_story_edit(story_id):
    story = Story.query.get_or_404(story_id)
    if request.method == 'POST':
        story.title = request.form.get('title')
        story.summary = request.form.get('summary')
        story.category = request.form.get('category')
        story.status = request.form.get('status')
        
        if 'cover_image' in request.files and request.files['cover_image'].filename:
            image = request.files['cover_image']
            picture_file = save_picture(image, 'story_covers')
            story.cover_image = picture_file
            
        db.session.commit()
        flash(f'"{story.title}" hikayesi güncellendi.', 'success')
        return redirect(url_for('admin_story_detail', story_id=story.id))
    
    return render_template('admin/story_edit.html', story=story)

@app.route('/admin/story/<int:story_id>/toggle_status', methods=['POST'])
@login_required
@admin_required
def admin_story_toggle_status(story_id):
    story = Story.query.get_or_404(story_id)
    status = request.form.get('status')
    if status in ['ongoing', 'completed', 'hiatus']:
        story.status = status
        db.session.commit()
        flash(f'"{story.title}" hikayesinin durumu değiştirildi.', 'success')
    return redirect(url_for('admin_story_detail', story_id=story.id))

@app.route('/admin/chapter/<int:chapter_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_chapter_delete(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    story_id = chapter.story_id
    story_title = chapter.story.title
    chapter_title = chapter.title
    
    db.session.delete(chapter)
    db.session.commit()
    
    flash(f'"{story_title}" hikayesinin "{chapter_title}" bölümü silindi.', 'success')
    return redirect(url_for('admin_story_detail', story_id=story_id))

@app.route('/story/<int:story_id>/toggle_status', methods=['POST'])
@login_required
def story_toggle_status(story_id):
    story = Story.query.get_or_404(story_id)
    
    # Check if user is the author or a collaborator
    if current_user != story.author:
        abort(403)
        
    status = request.form.get('status')
    if status in ['ongoing', 'completed', 'hiatus']:
        story.status = status
        db.session.commit()
        flash(f'"{story.title}" hikayesinin durumu değiştirildi.', 'success')
    
    return redirect(url_for('story', story_id=story.id))

@app.route('/admin/story/<int:story_id>/feature', methods=['POST'])
@login_required
@admin_required
def admin_story_feature(story_id):
    story = Story.query.get_or_404(story_id)
    feature_type = request.form.get('feature_type')
    action = request.form.get('action')
    award = request.form.get('award')
    
    if action == 'add':
        story.featured = True
        story.featured_date = datetime.now(pytz.utc)
        story.featured_type = feature_type
        
        if feature_type == 'editor_pick':
            story.editor_pick = True
        
        if award:
            story.award = award
            
        db.session.commit()
        flash(f'"{story.title}" hikayesi başarıyla öne çıkarıldı.', 'success')
    
    elif action == 'remove':
        story.featured = False
        
        if feature_type == 'editor_pick':
            story.editor_pick = False
        
        if award:
            story.award = None
            
        db.session.commit()
        flash(f'"{story.title}" hikayesi öne çıkarılanlardan kaldırıldı.', 'success')
    
    return redirect(url_for('admin_story_detail', story_id=story.id))

@app.route('/admin/editors')
@login_required
@admin_required
def admin_editors():
    editors = User.query.filter_by(is_editor=True).all()
    return render_template('admin/editors.html', editors=editors)

@app.route('/admin/toggle_editor/<int:user_id>')
@login_required
@admin_required
def admin_toggle_editor(user_id):
    user = User.query.get_or_404(user_id)
    
    # Cannot remove editor status from yourself
    if user.id == current_user.id:
        flash('Kendi editör statünüzü değiştiremezsiniz.', 'danger')
        return redirect(url_for('admin_editors'))
    
    # Toggle editor status
    user.is_editor = not user.is_editor
    db.session.commit()
    
    if user.is_editor:
        flash(f'{user.username} kullanıcısı editör yapıldı.', 'success')
    else:
        flash(f'{user.username} kullanıcısından editör yetkisi kaldırıldı.', 'success')
    
    return redirect(url_for('admin_editors'))

@app.route('/admin/test-story', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_test_story():
    if request.method == 'POST':
        title = request.form.get('title')
        category = request.form.get('category')
        summary = request.form.get('summary')
        cover_image = request.files.get('cover_image')

        if not all([title, category, summary]):
            flash('Lütfen tüm alanları doldurun.', 'error')
            return redirect(url_for('admin_create_test_story'))

        # Create test story
        story = Story(
            title=title,
            category=category,
            summary=summary,
            content='',
            author=current_user,
            status='ongoing'
        )

        # Handle cover image
        if cover_image and allowed_file(cover_image.filename):
            picture_file = save_picture(cover_image, 'story_covers')
            story.cover_image = picture_file

        db.session.add(story)
        db.session.commit()

        # Create test chapters with Lorem Ipsum content
        lorem_ipsum_chapters = [
            {
                "title": "Başlangıç",
                "content": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur."
            },
            {
                "title": "Gizemli Karşılaşma",
                "content": "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit."
            },
            {
                "title": "Beklenmedik Dönüş",
                "content": "At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga."
            },
            {
                "title": "Yeni Keşifler",
                "content": "Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet."
            },
            {
                "title": "Son",
                "content": "Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus."
            }
        ]

        for i, chapter_data in enumerate(lorem_ipsum_chapters, 1):
            chapter = Chapter(
                title=chapter_data["title"],
                content=chapter_data["content"],
                chapter_number=i,
                story=story
            )
            db.session.add(chapter)

        db.session.commit()
        flash('Test hikayesi başarıyla oluşturuldu.', 'success')
        return redirect(url_for('admin_stories'))

    return render_template('admin/create_test_story.html')

@app.route("/story/<int:story_id>/chapter/<int:chapter_id>")
def chapter(story_id, chapter_id):
    story = Story.query.get_or_404(story_id)
    chapter = Chapter.query.get_or_404(chapter_id)
    
    if chapter.story_id != story_id:
        abort(404)
    
    # Görüntülenme sayısını artır
    chapter.views += 1
    db.session.commit()
    
    # Önceki ve sonraki bölümleri bul
    prev_chapter = Chapter.query.filter(
        Chapter.story_id == story_id,
        Chapter.chapter_number < chapter.chapter_number
    ).order_by(Chapter.chapter_number.desc()).first()
    
    next_chapter = Chapter.query.filter(
        Chapter.story_id == story_id,
        Chapter.chapter_number > chapter.chapter_number
    ).order_by(Chapter.chapter_number.asc()).first()
    
    return render_template('chapter.html', 
                         title=f"{story.title} - {chapter.title}",
                         story=story,
                         chapter=chapter,
                         prev_chapter=prev_chapter,
                         next_chapter=next_chapter)

@app.route("/story/<int:story_id>/chapter/<int:chapter_id>/comment", methods=['POST'])
@login_required
def chapter_comment(story_id, chapter_id):
    story = Story.query.get_or_404(story_id)
    chapter = Chapter.query.get_or_404(chapter_id)
    
    if chapter.story_id != story_id:
        abort(404)
    
    content = request.form.get('content')
    if content:
        comment = ChapterComment(
            content=content,
            user_id=current_user.id,
            chapter_id=chapter_id
        )
        db.session.add(comment)
        db.session.commit()
        flash('Yorumunuz eklendi!', 'success')
    
    return redirect(url_for('chapter', story_id=story_id, chapter_id=chapter_id))

if __name__ == '__main__':
    with app.app_context():
        # Veritabanı ve tabloları kontrol et/oluştur
        try:
            print("Veritabanı kontrol ediliyor...")
            db.create_all()
            print("Veritabanı ve tablolar hazır.")
        except Exception as e:
            print(f"Veritabanı hatası: {str(e)}")
            sys.exit(1)
        
        # Admin hesabını kontrol et
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            try:
                print("Admin hesabı oluşturuluyor...")
                admin = User(
                    username='admin',
                    email='admin@example.com',
                    password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
                    created_at=datetime.now(pytz.utc),
                    last_login=datetime.now(pytz.utc),
                    bio='Site yöneticisi',
                    location='Türkiye',
                    social_media='@admin',
                    is_admin=True,
                    role=UserRole.ADMIN.value,
                    is_active=True
                )
                db.session.add(admin)
                db.session.commit()
                print("Admin hesabı oluşturuldu - Email: admin@example.com, Şifre: admin123")
            except Exception as e:
                print(f"Admin hesabı oluşturma hatası: {str(e)}")
        else:
            # Admin hesabının aktif olduğundan emin ol
            if not admin.is_active:
                admin.is_active = True
                db.session.commit()
                print("Admin hesabı aktif edildi.")
        
        # Test kullanıcısını kontrol et
        test_user = User.query.filter_by(email='test@example.com').first()
        if not test_user:
            try:
                print("Test kullanıcısı oluşturuluyor...")
                test_user = User(
                    username='test_user',
                    email='test@example.com',
                    password=bcrypt.generate_password_hash('test123').decode('utf-8'),
                    created_at=datetime.now(pytz.utc),
                    last_login=datetime.now(pytz.utc),
                    bio='Test kullanıcısı',
                    location='Türkiye',
                    social_media='@test_user',
                    is_admin=False,
                    role=UserRole.AUTHOR.value,
                    is_active=True
                )
                db.session.add(test_user)
                db.session.commit()
                print("Test kullanıcısı oluşturuldu - Email: test@example.com, Şifre: test123")
            except Exception as e:
                print(f"Test kullanıcısı oluşturma hatası: {str(e)}")
        
        print("\nUygulama başlatılıyor...")
        app.run(debug=True)
