# Similarity Engine Service

Phishing detection using typosquatting similarity algorithms.

## Setup

```bash
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

## Run

```bash
uvicorn app.main:app --reload --port 8000
```

## Docker

```bash
docker build -t similarity-engine .
docker run -p 8003:8000 --env-file .env similarity-engine
```

## Algorithms

Uses [ail-typo-squatting](https://github.com/typosquatter/ail-typo-squatting) library:

- **omission**: Leave out a letter (google → gogle)
- **repetition**: Repeat a character (google → gooogle)
- **replacement**: Replace a character (google → goagle)
- **homoglyph**: Use similar-looking characters (google → g00gle)
- **addition**: Add a character (google → googlee)
- **vowelswap**: Swap vowels (google → guugle)
- **subdomain**: Create subdomains (g.oogle.com)
- And more...
