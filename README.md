<div align="center">

# 🛡️ PhishGuard-CT

**Real-Time Certificate Transparency Phishing Detection & SOC Triage Platform**

[![CI](https://github.com/Bor-Code/Phishguard-Ct/actions/workflows/ci.yml/badge.svg)](https://github.com/Bor-Code/Phishguard-Ct/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-informational.svg)](CHANGELOG.md)
[![F1-Score](https://img.shields.io/badge/F1--Score-100%25-brightgreen.svg)](reports/evaluation_report.json)

</div>

---

## 🗺️ 1. Sistem Mimarisi (System Overview)

```mermaid
flowchart TD
    subgraph INGEST["1️⃣ Veri Kaynakları (Ingestion)"]
        CT["🌐 CertStream WebSocket\n(Canlı SSL/TLS Akışı)"]
        CLI_IN["💻 CLI / Batch Dosya\n(Tekil & Toplu Tarama)"]
        API_IN["🔌 REST API & Web UI\n(Anlık Analiz İstekleri)"]
    end

    subgraph ENGINE["2️⃣ Analiz & Puanlama Motoru"]
        NORM["🧹 Domain Temizleyici\n(Punycode & Wildcard)"]
        WL["🏷️ Marka İzleme Listesi\n(10 Marka + Alias Çözümleyici)"]
        SCORE["⚖️ 4 Sinyalli Benzerlik Motoru\n(Levenshtein • Klavye • Homoglif • Affix)"]
    end

    subgraph VERIFY["3️⃣ Aktif Doğrulama (Verification)"]
        DNS["🌍 DNS Çözümleyici\n(A / AAAA IP Kayıtları)"]
        HTTP["🔍 HTTP / HTML Probu\n(Login & Password Form Tespiti)"]
        TLS["🔐 Sertifika & TLD Analizi\n(Let's Encrypt / .xyz / .top)"]
    end

    subgraph OUTPUT["4️⃣ Depolama, Alarm & Görselleştirme"]
        DB[("🗄️ SQLite WAL\nVeritabanı")]
        DASH["📊 SOC Web Dashboard\n(Grafikler & Triyaj)"]
        WEBHOOK["🚨 Çoklu Kanal Alarm\n(Discord • Slack • Telegram)"]
    end

    CT & CLI_IN & API_IN --> NORM --> WL --> SCORE
    SCORE -->|"Skor >= Eşik (0.75)"| DNS & HTTP & TLS
    DNS & HTTP & TLS --> DB
    DB --> DASH
    DB -->|"Yüksek Güven"| WEBHOOK
```

---

## 🧠 2. 4 Sinyalli Puanlama Motoru Nasıl Çalışır?

```mermaid
flowchart LR
    D["Şüpheli Domain:\npaypa1-secure.xyz"] --> S1 & S2 & S3 & S4

    S1["📏 Levenshtein (%35)\nHarf Mesafesi"]
    S2["⌨️ Klavye (%25)\nKomşu Tuş Hatası"]
    S3["👁️ Homoglif (%25)\nSahte Karakter (l -> 1)"]
    S4["🧩 Affix / Token (%15)\nEk Kelime (-secure)"]

    S1 & S2 & S3 & S4 --> COMP["Bileşik Skor\n(0.00 - 1.00)"]
    COMP --> MULT["Aktif Doğrulama Çarpanı\n(x1.00 - x1.50)"]
    MULT --> FINAL["🎯 Nihai Güven Skoru"]
```

| Sinyal | Ağırlık | Yakaladığı Saldırı Tipi | Örnek |
| :--- | :---: | :--- | :--- |
| **Levenshtein** | `%35` | Harf ekleme / silme / değiştirme | `paypaI.com`, `gooogle.com` |
| **Keyboard** | `%25` | QWERTY klavyede komşu tuşa basma | `payoal.com`, `gppgle.com` |
| **Homoglyph** | `%25` | Görsel ikiz harfler (`0`/`o`, `1`/`l`, Kiril) | `paypa1.com`, `faceb00k.com` |
| **Affix / Subdomain** | `%15` | Marka + yanıltıcı ek kelimeler | `paypal-login-verify.xyz` |

---

## 🔄 3. Tehdit Yaşam Döngüsü (SOC Triage State Flow)

```mermaid
stateDiagram-v2
    [*] --> Candidate: Sertifika / URL Gelir
    Candidate --> Legitimate: Resmi Marka Domaini (Allowlist)
    Candidate --> LowRisk: Skor < 0.75
    Candidate --> flagged: Skor >= 0.75 (Veritabanına Kayıt)
    flagged --> alert_sent: Webhook Bildirimi Gönderildi
    flagged --> confirmed: Analist Onayladı (Gerçek Phishing)
    alert_sent --> confirmed: Analist Onayladı
    flagged --> dismissed: Analist Reddetti (Yanlış Alarm)
    alert_sent --> dismissed: Analist Reddetti
```

---

## 🖥️ 4. SOC Web Dashboard Görünümü

```text
+-----------------------------------------------------------------------------------+
| 🛡️ PhishGuard-CT SOC Console v1.0.0          [Export JSON] [Export CSV] [Refresh] |
+--------------------+--------------------------------------------------------------+
| ▸ Overview & Charts|  [ Flagged: 24 ]  [ Live Threats: 18 ]  [ Brands: 10 ]       |
| ▸ Threat Explorer  |                                                              |
| ▸ Batch Scanner    |  +----------------------+  +------------------------------+  |
| ▸ Brand Watchlist  |  |  (O) Status Donut    |  |  Critical >=0.90 [████████]  |  |
|                    |  |      flagged / sent  |  |  High 0.75-0.89  [█████   ]  |  |
|                    |  +----------------------+  +------------------------------+  |
|                    |                                                              |
|                    |  Domain                        Brand    Score    Actions     |
|                    |  ----------------------------------------------------------  |
|                    |  paypa1-secure-verify.com      paypal   0.9850   [Inspect]   |
|                    |  g00gle-workspace-sso.xyz      google   0.9240   [Confirm]   |
+--------------------+--------------------------------------------------------------+
```

---

## ⚡ 5. Hızlı Başlangıç (Quick Start)

### Kurulum

```bash
git clone https://github.com/Bor-Code/Phishguard-Ct.git
cd Phishguard-Ct
python -m venv .venv
.\.venv\Scripts\activate   # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

### Temel Komutlar

| Amaç | Komut |
| :--- | :--- |
| **🌐 Web Dashboard & API Başlat** | `phishguard serve --host 127.0.0.1 --port 8080` |
| **📡 Canlı CT Akışını İzle** | `phishguard monitor --min-score 0.75` |
| **🔍 Tekil Domain / URL Tara** | `phishguard scan paypa1-login.xyz --json` |
| **📂 Toplu Dosya Tara** | `phishguard batch domains.txt --output results.json` |
| **📤 Veritabanını Dışa Aktar** | `phishguard export threats.csv --format csv` |
| **🧪 Benchmark Testini Çalıştır** | `phishguard evaluate --output-dir reports` |

---

## 🔌 6. REST API Uç Noktaları

```mermaid
sequenceDiagram
    participant Analyst as 👨‍💻 SOC Analisti / UI
    participant API as 🚀 PhishGuard API (:8080)
    participant DB as 🗄️ SQLite DB

    Analyst->>API: GET /stats
    API->>DB: Özet metrikleri ve dağılımları oku
    DB-->>API: KPI + Grafikler
    API-->>Analyst: 200 OK (JSON)

    Analyst->>API: POST /scan {"domain": "paypa1-secure.com", "save": true}
    API->>DB: Şüpheli kaydı sakla
    API-->>Analyst: 200 OK (Skor + Sinyaller)

    Analyst->>API: PATCH /domains/paypa1-secure.com {"status": "confirmed"}
    API->>DB: Durumu 'confirmed' olarak güncelle
    API-->>Analyst: 200 OK
```

| Metot | Uç Nokta | Açıklama |
| :---: | :--- | :--- |
| `GET` | `/` veya `/dashboard` | İnteraktif SOC Web Arayüzü |
| `GET` | `/health` | Servis sağlık ve versiyon kontrolü |
| `GET` | `/stats` | Grafik ve KPI istatistikleri |
| `GET` | `/domains` | Yakalanan domain listesi (`?brand=`, `?status=`, `?min_score=`) |
| `GET` | `/domains/{domain}` | Tekil domain tam analiz ve sertifika detayı |
| `PATCH` | `/domains/{domain}` | Analist durum güncellemesi (`confirmed` / `dismissed`) |
| `POST` | `/scan` | Tekil domain/URL anlık analizi |
| `POST` | `/batch-scan` | Çoklu domain toplu analizi |
| `GET` | `/watchlist` | Korunan markalar ve anahtar kelimeler |
| `GET` | `/export` | `JSON` veya `CSV` rapor indirme (`?format=csv`) |

---

## 📊 7. Benchmark Sonuçları

| Metrik | Sonuç |
| :--- | :---: |
| **Toplam Örneklem** | `44` (`24` Oltalama / `20` Güvenli) |
| **Doğru Pozitif (TP) / Yanlış Pozitif (FP)** | `24` / `0` |
| **Kesinlik (Precision)** | **`100%` (`1.0000`)** |
| **Duyarlılık (Recall)** | **`100%` (`1.0000`)** |
| **F1-Skoru** | **`100%` (`1.0000`)** |

---

## 🐳 8. Docker & Testler

```bash
# Docker ile çalıştırma
docker compose up -d --build

# Birim testlerini çalıştırma
pytest
```

---

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.
