from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime
import os
import bcrypt
from werkzeug.utils import secure_filename
import time
from PIL import Image
import secrets
from dateutil import tz
import pytz
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Bu sayfayı görüntülemek için lütfen giriş yapın.'
login_manager.login_message_category = 'info'

# Veritabanı klasörünü oluştur
if not os.path.exists('instance'):
    os.makedirs('instance')

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
    stories = db.relationship('Story', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    collaborations = db.relationship('StoryCollaborator', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

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
        DataRequired(message='Şifre gerekli')
    ])
    remember = BooleanField('Beni Hatırla')
    submit = SubmitField('Giriş Yap')

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
    username = StringField('Kullanıcı Adı', validators=[DataRequired()])
    role = SelectField('Rol', choices=[
        ('author', 'Yazar'),
        ('editor', 'Editör'),
        ('translator', 'Çevirmen')
    ], validators=[DataRequired()])
    submit = SubmitField('Yazar Ekle')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    stories = Story.query.order_by(Story.date_posted.desc()).all()
    categories = ['Macera', 'Romantik', 'Bilim Kurgu', 'Fantastik', 'Gizem', 'Korku', 'Dram', 'Komedi', 'Diğer']
    return render_template('home.html', stories=stories, categories=categories)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            user.last_login = datetime.now(pytz.utc)
            db.session.commit()
            next_page = request.args.get('next')
            flash(f'Hoş geldiniz, {user.username}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Giriş başarısız. Lütfen e-posta ve şifrenizi kontrol edin.', 'danger')
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
                password=hashed_password
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

@app.route("/write", methods=['GET', 'POST'])
@login_required
def write_story():
    form = StoryForm()
    if form.validate_on_submit():
        story = Story(
            title=form.title.data,
            category=form.category.data,
            summary=form.summary.data,
            content='',  # İçerik bölümler aracılığıyla eklenecek
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
def add_chapter(story_id):
    story = Story.query.get_or_404(story_id)
    if story.author != current_user:
        abort(403)
    
    form = ChapterForm()
    if form.validate_on_submit():
        # Bir sonraki bölüm numarasını belirle
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
    if current_user != story.author:
        abort(403)
    form = CollaboratorForm()
    if form.validate_on_submit():
        collaborator = User.query.filter_by(username=form.username.data).first()
        if collaborator is None:
            flash('Kullanıcı bulunamadı.', 'danger')
            return redirect(url_for('add_collaborator', story_id=story_id))
        if collaborator == current_user:
            flash('Kendinizi ortak yazar olarak ekleyemezsiniz.', 'danger')
            return redirect(url_for('add_collaborator', story_id=story_id))
        existing_collab = StoryCollaborator.query.filter_by(
            story_id=story.id, user_id=collaborator.id).first()
        if existing_collab:
            flash('Bu kullanıcı zaten ortak yazar.', 'warning')
            return redirect(url_for('add_collaborator', story_id=story_id))
        
        collaboration = StoryCollaborator(
            user_id=collaborator.id,
            story_id=story.id,
            role=form.role.data
        )
        db.session.add(collaboration)
        db.session.commit()
        flash(f'{collaborator.username} ortak yazar olarak eklendi.', 'success')
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
