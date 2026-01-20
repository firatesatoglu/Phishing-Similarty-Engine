# Phishing Similarity Engine

Domain similarity and typosquatting detection service for phishing analysis.

![API Documentation](docs/similarity-engine-api-docs.png)

## Features

- **Typosquatting search** - Generate and match domain variations
- **Similarity search** - Levenshtein, Jaro-Winkler algorithms
- **Keyword search** - Find domains containing specific keywords
- **Homograph detection** - Unicode/IDN attack detection
- **Optimized queries** - Length-based pre-filtering for performance

## Installation

### Requirements

- Python 3.11+
- MongoDB 5.0+ (shared database with zone-collector)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file:

```bash
MONGODB_URL=mongodb://user:pass@localhost:27017/
DATABASE_NAME=icann_tlds_db
```

## Running

### Local

```bash
uvicorn app.main:app --reload --port 8003
```

### Docker

```bash
docker build -t similarity-engine .
docker run -p 8003:8000 --env-file .env similarity-engine
```

## API Endpoints

### Health & Info

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/algorithms` | GET | Available algorithms |

### Search

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/search/typosquatting` | POST | Typosquatting variations |
| `/search/similarity` | POST | String similarity search |
| `/search/keyword` | POST | Keyword inclusion search |

---

## POST `/search/typosquatting`

Search for typosquatting variations of a brand.

### Request

```json
{
  "brand_name": "google.com",
  "days_back": 7,
  "algorithms": ["omission", "homoglyph"],
  "tlds": ["com", "net"]
}
```

### Response

```json
{
  "brand": "google.com",
  "brand_extracted": "google",
  "total_variations": 150,
  "matched_variations": 5,
  "variations": [
    {
      "variation": "gogle",
      "matched": true,
      "matches": [{ "fqdn": "gogle.com", "first_seen": "..." }]
    }
  ]
}
```

---

## POST `/search/similarity`

Search for similar domains using string similarity algorithms.

### Request

```json
{
  "brand_name": "google.com",
  "days_back": 7,
  "levenshtein_threshold": 0.70,
  "jaro_winkler_threshold": 0.75,
  "homograph_enabled": true,
  "tlds": ["com", "net"]
}
```

### Response

```json
{
  "brand_extracted": "google",
  "domains_scanned": 1500,
  "results": {
    "levenshtein": [{ "domain": "gogle", "similarity": 0.83 }],
    "jaro_winkler": [{ "domain": "googel", "similarity": 0.94 }],
    "homograph": [{ "domain": "gооgle", "risk_level": "critical" }]
  }
}
```

### Performance Optimization

Similarity search uses **length-based pre-filtering**:

```
brand: "google" (6 chars)
length_tolerance: 3
→ Only scans domains with 3-9 characters
→ Reduces computation by 90%+
```

---

## POST `/search/keyword`

Find domains CONTAINING a specific keyword.

### Request

```json
{
  "keyword": "google",
  "days_back": 7,
  "tlds": ["com", "net"],
  "limit": 500
}
```

### Response

```json
{
  "keyword": "google",
  "total_matches": 25,
  "matches": [
    { "domain": "mygoogle", "fqdn": "mygoogle.com" },
    { "domain": "google-login", "fqdn": "google-login.net" }
  ]
}
```

---

## Typosquatting Algorithms

| Algorithm | Example |
|-----------|---------|
| `omission` | google → gogle |
| `repetition` | google → gooogle |
| `replacement` | google → goagle |
| `homoglyph` | google → g00gle |
| `addition` | google → googlee |
| `vowel_swap` | google → guugle |
| `numeral_swap` | one → 1 |

---

## Similarity Algorithms

### Levenshtein

Edit distance similarity. Default threshold: `0.70`

```
"google" vs "gogle" → 0.83 (1 deletion)
```

### Jaro-Winkler

Prefix-weighted similarity. Default threshold: `0.75`

```
"google" vs "googel" → 0.94 (strong prefix)
```

### Homograph

Unicode look-alike detection:

```
"google" vs "gооgle" (Cyrillic о) → Detected
Risk levels: critical, high, medium, low
```

---

## Architecture

```
similarity-engine/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── api/routes.py           # Endpoints + request models
│   ├── database/mongodb.py     # Optimized queries
│   └── services/
│       ├── typosquatting.py    # Variation generator
│       └── string_similarity.py # Similarity algorithms
└── requirements.txt
```

## Performance

| Operation | Time |
|-----------|------|
| Typosquatting | ~100ms |
| Similarity (with filter) | ~500ms |
| Keyword search | ~50ms |
