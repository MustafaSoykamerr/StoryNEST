from app import app, db, User, Story, bcrypt
from datetime import datetime, timezone

def init_db():
    print("Veritabanı sıfırlanıyor...")
    with app.app_context():
        db.drop_all()
        db.create_all()

        # Admin kullanıcısı oluştur
        admin = User(
            username='admin',
            email='admin@example.com',
            password=bcrypt.generate_password_hash('admin123').decode('utf-8'),
            created_at=datetime.now(timezone.utc),
            last_login=datetime.now(timezone.utc),
            bio='Site yöneticisi',
            location='Türkiye',
            social_media='@admin'
        )

        # Test kullanıcısı oluştur
        test_user = User(
            username='test_user',
            email='test@example.com',
            password=bcrypt.generate_password_hash('test123').decode('utf-8'),
            created_at=datetime.now(timezone.utc),
            last_login=datetime.now(timezone.utc),
            bio='Test kullanıcısı',
            location='Türkiye',
            social_media='@test_user'
        )

        # Kullanıcıları veritabanına ekle
        db.session.add(admin)
        db.session.add(test_user)
        db.session.commit()

        # Test hikayesi oluştur
        test_story = Story(
            title='Test Hikayesi',
            content='Bu bir test hikayesidir.',
            summary='Test hikayesi özeti',
            category='Fantastik',
            author=test_user
        )

        # Hikayeyi veritabanına ekle
        db.session.add(test_story)
        db.session.commit()

        print("Veritabanı başarıyla sıfırlandı ve test verileri eklendi.")
        print("Admin kullanıcısı - Email: admin@example.com, Şifre: admin123")
        print("Test kullanıcısı - Email: test@example.com, Şifre: test123")

if __name__ == '__main__':
    init_db()
