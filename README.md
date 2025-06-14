# 🔐 Auth Service

NestJS ile geliştirilen bu Authentication Microservice, JWT tabanlı kimlik doğrulama, rol bazlı yetkilendirme ve çoklu oturum yönetimi gibi kapsamlı özellikler sunar. Bu servis, Nest tabanlı projelerde kolayca entegre edilebilecek şekilde modüler olarak tasarlanmıştır.

```
🧑 → 🔐 Giriş → 🪪 Access Token + 🍪 Refresh Token

🔐 Access Token → API'lere erişim → ⏰ Süre biterse...

🍪 Refresh Token → /refresh-access → 🔄 Yeni Access Token

🚪 Çıkış → Cookie silinir → Oturum sonlanır
```


## 🚀 Özellikler

- ✅ JWT tabanlı kimlik doğrulama (Access & Refresh Token desteği)
- 🎭 Rol bazlı yetkilendirme (örn: `admin`, `employee`)
- 📱 Çoklu cihaz oturum yönetimi (tek cihazdan veya tüm cihazlardan çıkış)
- 🔒 Güvenli cookie yönetimi (`httpOnlyCookie`)
- 📝 Kullanıcı işlemleri: kayıt, giriş, şifre değiştirme, e-posta değiştirme
- 📚 Swagger ile otomatik API dokümantasyonu
- 🗄️ TypeORM üzerinden PostgreSQL desteği
- 🔄 Transactional servis mimarisi
- 🛡️ Gelişmiş Guard, Decorator ve Strategy kullanımı
- 📋 Uygulama genelinde gelişmiş loglama (login denemeleri, hatalar, güvenlik olayları)

## 🛠️ Kullanılan Teknolojiler

| Teknoloji         | Açıklama                             |
|------------------|--------------------------------------|
| **NestJS**        | Backend uygulama çatısı              |
| **TypeORM**       | ORM ve migration yönetimi            |
| **PostgreSQL**    | Veritabanı                           |
| **Passport.js**   | JWT ve authentication stratejileri   |
| **Swagger**       | API dökümantasyonu                   |
| **bcrypt**        | Şifre hashleme                       |
| **cookie-parser** | Cookie yönetimi                      |
| **helmet**        | Güvenlik için HTTP başlıkları        |
| **compression**   | Performans için sıkıştırma           |
| **Jest**          | Test altyapısı                       |
| **dotenv**        | Ortam değişkenleri yönetimi          |


## 🔒 Güvenlik Mimarisine Genel Bakış

- **JWT Guard**: Tüm korumalı endpointlerde zorunludur.
- **Role Guard**: Sadece `admin` gibi özel erişim gereken endpointlerde kullanılır.
- **Refresh Token**: `httpOnly` ve (production ortamında) `secure` olarak cookie'de saklanır.
- **Access Token**: Header üzerinden taşınır, süresi dolduğunda `refresh-access` endpointiyle yenilenir.
- **Logout**:
  - Tek cihazdan çıkış
  - Tüm cihazlardan çıkış
  - Her iki durumda da cookie temizlenir.
- **Production ortamında**:
  - `NODE_ENV=production` ayarı ile `secure: true` cookie zorunluluğu aktifleşir.
  - Local ortamda `development` olarak çalışır.

## 👤 Kullanıcı Rolleri ve Yetkilendirme

- Yeni kullanıcılar varsayılan olarak `employee` rolüyle oluşturulur.
- `admin` erişimi gerektiren endpointlerde `RoleGuard("admin")` devreye girer.
- Tüm JWT korumalı endpointlerde geçerli bir `access token` gereklidir.

## 🧩 Geliştirici Notları

- Modüler yapısı sayesinde bu Auth servisi farklı projelere kolayca entegre edilebilir.
- İsteğe bağlı olarak bağımsız bir npm paketi haline getirilebilir.
- Transactional servis yapısı sayesinde veri tutarlılığı ve güvenliği korunur.


## 📄 Ortam Değişkenleri (`.env` Örneği)
```env
# 🔐 TOKEN Ayarları
JWT_SECRET=your_jwt_secret_key_here
JWT_EXPIRES_IN=15m                 # Access token süresi (örn: 15 dakika)
REFRESH_TOKEN_EXPIRES_IN=604800000 # Refresh token süresi (ms cinsinden, burada 7 gün)

# 🗄️ Veritabanı Ayarları
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=your_db_username
DB_PASSWORD=your_db_password
DB_NAME=your_db_name

# 🌐 Server Ayarları
PORT=3000                          # API sunucu portu

# ⚙️ Ortam (development, production)
NODE_ENV=development

```

## 🔐 Auth (Kimlik Doğrulama) Endpointleri

| HTTP Yöntemi | Endpoint                 | Açıklama                                      |
|--------------|--------------------------|-----------------------------------------------|
| POST         | `/api/auth/login`         | Kullanıcı girişi. Access ve refresh token oluşturur. |
| POST         | `/api/auth/register`      | Yeni kullanıcı kaydı.                          |
| GET          | `/api/auth/current-user`  | Mevcut token’a göre aktif kullanıcı bilgisi döner. |
| POST         | `/api/auth/refresh-access`| Access token süresi dolduğunda yeniler.       |
| POST         | `/api/auth/logout`        | Mevcut cihazdan çıkış yapar, refresh token silinir. |
| POST         | `/api/auth/logout-all`    | Kullanıcının tüm cihazlarından çıkış yapar.   |
| POST         | `/api/auth/force-logout/{userId}` | Admin tarafından belirli kullanıcıyı zorla çıkarma. |
| PUT          | `/api/auth/change-password` | Kullanıcı şifresini değiştirir.             |
| PUT          | `/api/auth/change-email`  | Kullanıcı e-posta adresini değiştirir.        |
| GET          | `/api/auth/deneme`        | Test amaçlı endpoint.                          |

---

## 👤 Kullanıcı Yönetimi Endpointleri

| HTTP Yöntemi | Endpoint                      | Açıklama                                    |
|--------------|-------------------------------|---------------------------------------------|
| POST         | `/api/users`                  | Yeni kullanıcı oluşturur.                    |
| GET          | `/api/users`                  | Tüm kullanıcıları listeler.                  |
| GET          | `/api/users/{id}`             | Belirtilen ID’ye sahip kullanıcıyı getirir. |
| PUT          | `/api/users/{id}`             | Kullanıcı bilgilerini günceller.            |
| DELETE       | `/api/users/{id}`             | Kullanıcıyı soft delete (pasifleştirir).   |
| DELETE       | `/api/users/{id}/hard-delete`| Kullanıcıyı kalıcı olarak siler.            |
| PUT          | `/api/users/{id}/disable`     | Kullanıcıyı devre dışı bırakır.             |
| PUT          | `/api/users/{id}/enable`      | Devre dışı bırakılan kullanıcıyı aktif eder.|
| PUT          | `/api/users/{id}/role`        | Kullanıcının rolünü (admin/employee) değiştirir. |

---

## 🧪 Swagger UI
API dökümantasyonuna tarayıcıdan şu adresten ulaşabilirsiniz:

```
http://localhost:PORT/swagger
```

Tüm API endpointlerini ve detaylarını Swagger arayüzünden görüntüleyebilirsiniz:

