# Similarity Engine Service

Typosquatting and phishing detection service - performs domain similarity analysis.

## Features

- Typosquatting variation generation and search
- Levenshtein distance similarity
- Jaro-Winkler similarity
- Homograph (Unicode) detection
- Customizable algorithms with separate thresholds
- Date range and TLD-based filtering

## Installation

### Requirements

- Python 3.11+
- MongoDB 5.0+ (shared with zone-collector)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file:

```bash
# MongoDB (same database as zone-collector)
MONGODB_URL=mongodb://user:pass@localhost:27017/
MONGODB_DB=icann_tlds_db
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
| `/` | GET | Swagger UI |
| `/api/v1/health` | GET | Health check |
| `/api/v1/algorithms` | GET | Supported algorithm list |

### Typosquatting Search

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/search/typosquatting` | POST | Search typosquatting variations |
| `/api/v1/preview-variations` | POST | Variation preview |

### Similarity Search

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/search/similarity` | POST | String similarity search |

---

## Typosquatting API

### POST `/api/v1/search/typosquatting`

Searches for possible typosquatting variations of a domain in the database.

#### Request Body

```json
{
  "domain": "google.com",           // Required: domain.tld format
  "days_back": 7,                   // Optional: days to look back (default: 7)
  "algorithms": ["homoglyph", "omission"]  // Optional: algorithm filter
}
```

> ⚠️ The `domain` parameter **must** be in `domain.tld` format (e.g., `google.com`). Just `google` is not accepted.

#### Response

```json
{
  "brand": "google",
  "domain": "google.com",
  "search_params": {
    "days_back": 7,
    "algorithms": ["homoglyph", "omission"],
    "tlds_searched": ["com", "net", "org"]
  },
  "matches": [
    {
      "domain": "g00gle.com",
      "tld": "com",
      "first_seen": "2024-12-20T10:30:00Z",
      "algorithm": "homoglyph",
      "variation_type": "homoglyph"
    }
  ],
  "total_matches": 15,
  "execution_time_ms": 245
}
```

---

## Similarity API

### POST `/api/v1/search/similarity`

Searches for similar domains using string similarity algorithms.

#### Request Body

```json
{
  "brand_name": "google.com",       // Required: brand or domain
  "days_back": 7,                   // Optional: days to look back (default: 7)
  "levenshtein_threshold": 0.70,    // Optional: Levenshtein threshold (default: 0.70)
  "jaro_winkler_threshold": 0.75,   // Optional: Jaro-Winkler threshold (default: 0.75)
  "homograph_enabled": true,        // Optional: Homograph check (default: true)
  "tlds": ["com", "net"]            // Optional: TLD filter
}
```

> 💡 `brand_name` accepts both `google` and `google.com` formats.

#### Response

```json
{
  "brand": "google",
  "search_params": {
    "days_back": 7,
    "levenshtein_threshold": 0.70,
    "jaro_winkler_threshold": 0.75,
    "homograph_enabled": true,
    "tlds": ["com", "net"]
  },
  "results": {
    "levenshtein": [
      {
        "domain": "gogle.com",
        "tld": "com",
        "score": 0.857,
        "first_seen": "2024-12-20T10:30:00Z"
      }
    ],
    "jaro_winkler": [
      {
        "domain": "googel.com",
        "tld": "com",
        "score": 0.944,
        "first_seen": "2024-12-21T08:15:00Z"
      }
    ],
    "homograph": [
      {
        "domain": "gооgle.com",
        "tld": "com",
        "homograph_chars": ["о→o", "о→o"],
        "first_seen": "2024-12-22T14:00:00Z"
      }
    ]
  },
  "summary": {
    "levenshtein_count": 5,
    "jaro_winkler_count": 8,
    "homograph_count": 2,
    "total": 15
  },
  "execution_time_ms": 1250
}
```

---

## Typosquatting Algorithms

Uses the [ail-typo-squatting](https://github.com/typosquatter/ail-typo-squatting) library:

| Algorithm | Description | Example |
|-----------|-------------|---------|
| `omission` | Leave out a letter | google → gogle |
| `repetition` | Repeat a character | google → gooogle |
| `replacement` | Replace a character (QWERTY) | google → goagle |
| `homoglyph` | Similar-looking characters | google → g00gle |
| `addition` | Add a character | google → googlee |
| `vowel_swap` | Swap vowels | google → guugle |
| `subdomain` | Create subdomains | goo.gle → g.oogle |
| `numeral_swap` | Number-letter swap | one → 1 |
| `bitsquatting` | Bit-flip variations | google → coogle |
| `wrong_tld` | Wrong TLD | google.com → google.co |

---

## Similarity Algorithms

### Levenshtein Distance

Edit distance-based similarity measurement. Calculates the minimum number of edits between two strings.

```
Formula: 1 - (edit_distance / max(len(s1), len(s2)))

Example:
  "google" vs "gogle" → 1 deletion → score: 0.833
  "google" vs "googel" → 1 transposition → score: 0.833
```

**Default Threshold:** `0.70`

### Jaro-Winkler

Prefix-weighted similarity. Gives higher scores when string beginnings match.

```
Example:
  "google" vs "gooogle" → score: 0.952 (strong prefix match)
  "google" vs "elgoog" → score: 0.611 (weak match)
```

**Default Threshold:** `0.75`

### Homograph Detection

Detects Unicode look-alike characters:

```
Example:
  "google" vs "gооgle" (Cyrillic 'о') → Homograph detected
  "apple" vs "аpple" (Cyrillic 'а') → Homograph detected
```

**Detected Characters:**
- Cyrillic: а, е, о, р, с, х, у (looks like a, e, o, p, c, x, y)
- Greek: α, β, ε, ι, κ, ο, ρ, τ, υ
- Special: І, ı, ℓ, ﬁ, ﬂ

---

## Architecture

```
similarity-engine/
├── app/
│   ├── main.py              # FastAPI app
│   ├── config.py            # Settings (Pydantic)
│   ├── api/
│   │   └── routes.py        # API endpoints, request/response models
│   ├── database/
│   │   └── mongodb.py       # MongoDB queries
│   └── services/
│       ├── typosquatting.py # Variation generation
│       └── string_similarity.py  # Similarity algorithms
├── requirements.txt
├── Dockerfile
└── .env
```

## Performance

| Operation | Average Time |
|-----------|--------------|
| Typosquatting (single TLD) | ~50ms |
| Typosquatting (all TLDs) | ~500ms |
| Similarity (7 days, 3 TLDs) | ~1-2s |
| Similarity (30 days, all TLDs) | ~10-30s |

> 💡 Similarity search scans all domains, so using `days_back` and `tlds` filters improves performance.

## Error Codes

| HTTP | Description |
|------|-------------|
| 400 | Invalid domain format |
| 404 | TLD not found |
| 500 | Internal server error |
| 503 | MongoDB connection error |
