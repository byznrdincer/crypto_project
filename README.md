#  Kriptoloji Projesi — İstemci–Sunucu Şifreleme Uygulaması (Caesar Cipher)

Bu proje, **kriptoloji dersi** kapsamında geliştirilen bir **istemci–sunucu (client–server)** yapısında çalışan **Caesar Cipher (Kaydırma Şifreleme)** uygulamasıdır.

Kullanıcı, web arayüzü üzerinden mesajını ve anahtar değerini girerek mesajı şifreleyebilir veya sunucu tarafında deşifre edebilir.

---

##  Proje Amacı

Bu uygulamanın temel amacı, klasik şifreleme algoritmalarının (örneğin Caesar, Vigenère, Hill vb.) **istemci–sunucu mimarisi** üzerinde nasıl çalıştığını anlamaktır.

📘 Proje adım adım geliştirilecektir:
- 🔹 **1. Hafta:** Caesar Cipher (Kaydırma)
- 🔹 **2. Hafta:** Vigenère Cipher
- 🔹 **3. Hafta:** Hill Cipher
- 🔹 **4. Hafta:** AES / RSA (kütüphanesiz)
- 🔹 **5. Hafta:** Wireshark ile ağ trafiği analizi

---

## ⚙️ Kullanılan Teknolojiler

| Katman | Teknoloji | Açıklama |
|--------|------------|-----------|
|  Backend | **Python / Django** | Şifreleme işlemleri ve API yönetimi |
|  Frontend | **HTML5, Bootstrap 5, JavaScript** | Kullanıcı arayüzü |
|  İletişim | **Fetch (AJAX)** | İstemci ile sunucu arasında veri aktarımı |
|  Şifreleme | **Caesar Cipher** | Harf kaydırma temelli klasik şifreleme algoritması |

---

## 💡 Uygulama Özeti

🔹 **İstemci (Client)**  
Kullanıcı arayüzünden mesaj ve kaydırma anahtarı girilir.  
Arayüz, bu verileri `POST` isteğiyle `/encrypt/` endpoint’ine gönderir.

🔹 **Sunucu (Server)**  
Sunucu, gelen isteği alır, Caesar Cipher algoritmasını uygular ve şifreli sonucu JSON formatında geri döner.  
Aynı şekilde `/decrypt/` endpoint’i ile şifre çözme işlemi yapılır.
