from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
import logging

from app.services.similarity import similarity_service
from app.services.typosquatting import typo_generator
from app.services.string_similarity import string_similarity
from app.database.mongodb import mongodb
from app.config import settings
import tldextract

logger = logging.getLogger(__name__)

health_router = APIRouter(tags=["Health"])
search_router = APIRouter(tags=["Search"])
algorithms_router = APIRouter(tags=["Algorithms"])



class TyposquattingRequest(BaseModel):
    """Request model for typosquatting search."""
    brand_name: str = Field(
        ..., 
        description="Brand or domain name to search for (e.g., 'google.com' or 'google')",
        examples=["google.com", "microsoft", "getir"]
    )
    days_back: Optional[int] = Field(
        default=7,
        description="Number of days back to search. Default is 7.",
        ge=1,
        le=365
    )
    algorithms: Optional[List[str]] = Field(
        default=None,
        description="Typosquatting algorithms to use. Empty means use all.",
        examples=[["omission", "homoglyph"], ["all"]]
    )
    tlds: Optional[List[str]] = Field(
        default=None,
        description="TLDs to search in. Empty means all available.",
        examples=[["zip", "com"], []]
    )


class SimilarityRequest(BaseModel):
    """Request model for similarity search."""
    brand_name: str = Field(
        ..., 
        description="Brand or domain name to search for",
        examples=["google.com", "getir"]
    )
    days_back: Optional[int] = Field(
        default=7,
        description="Number of days back to search.",
        ge=1,
        le=365
    )
    levenshtein_threshold: Optional[float] = Field(
        default=0.70,
        description="Minimum Levenshtein similarity score (0-1). Default 0.70",
        ge=0.0,
        le=1.0
    )
    jaro_winkler_threshold: Optional[float] = Field(
        default=0.75,
        description="Minimum Jaro-Winkler similarity score (0-1). Default 0.75",
        ge=0.0,
        le=1.0
    )
    homograph_enabled: Optional[bool] = Field(
        default=True,
        description="Enable homograph/IDN attack detection"
    )
    tlds: Optional[List[str]] = Field(
        default=None,
        description="TLDs to search in. Empty means all available."
    )


class KeywordRequest(BaseModel):
    """Request model for keyword inclusion search."""
    keyword: str = Field(
        ..., 
        description="Keyword to search for in domain names",
        examples=["google", "paypal", "microsoft"]
    )
    days_back: Optional[int] = Field(
        default=7,
        description="Number of days back to search.",
        ge=1,
        le=365
    )
    tlds: Optional[List[str]] = Field(
        default=None,
        description="TLDs to search in. Empty means all available."
    )
    limit: Optional[int] = Field(
        default=500,
        description="Maximum results to return",
        ge=1,
        le=5000
    )


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    mongodb_connected: bool


class AlgorithmInfo(BaseModel):
    """Algorithm information."""
    name: str
    category: str
    description: str



@health_router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    mongodb_connected = False
    try:
        if mongodb.client:
            await mongodb.client.admin.command("ping")
            mongodb_connected = True
    except Exception:
        pass
    
    return HealthResponse(
        status="healthy" if mongodb_connected else "degraded",
        mongodb_connected=mongodb_connected
    )



def extract_brand_name(brand_input: str) -> tuple[str, str]:
    """
    Extract just the brand/domain name and TLD from input.
    Returns (domain_name, tld)
    """
    extracted = tldextract.extract(brand_input)
    if extracted.domain and extracted.suffix:
        return extracted.domain.lower(), extracted.suffix.lower()
    return None, None


def validate_domain_input(brand_name: str) -> tuple[str, str]:
    """
    Validate that input is in domain.tld format.
    Returns (domain, tld) or raises HTTPException.
    """
    domain, tld = extract_brand_name(brand_name)
    if not domain or not tld:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid format",
                "message": "Please enter domain in 'domain.tld' format (e.g., 'getir.com', 'google.com.tr')",
                "received": brand_name
            }
        )
    return domain, tld


@search_router.post("/search/typosquatting")
async def search_typosquatting(request: TyposquattingRequest):
    """
    Search for typosquatting domains.
    
    This endpoint:
    1. Generates typosquatting variations of the brand name
    2. Returns ALL generated variations
    3. For each variation, includes database match info if found
    
    **Input format:** domain.tld (e.g., getir.com, google.com.tr)
    
    **Algorithms used:** omission, repetition, replacement, homoglyph, etc.
    """
    start_time = datetime.utcnow()
    
    logger.info(f"🔍 Typosquatting search: brand='{request.brand_name}', days_back={request.days_back or 7}")
    
    brand, tld = validate_domain_input(request.brand_name)
    
    now = datetime.utcnow()
    end_date = datetime(now.year, now.month, now.day) + timedelta(days=1)
    start_date = end_date - timedelta(days=request.days_back or 7)
    
    full_domain = f"www.{brand}.{tld}"
    variation_result = typo_generator.generate_variations(
        domain=full_domain,
        algorithms=request.algorithms,
        limit=settings.max_variations
    )
    
    variations = set(variation_result["variations"])
    variations.add(brand)  # Include original
    
    matches = await mongodb.find_matching_domains(
        domain_variations=variations,
        start_date=start_date,
        end_date=end_date,
        tlds_filter=request.tlds
    )
    
    matched_lookup = {}
    for match in matches:
        domain = match.get("domain", "").lower()
        if domain not in matched_lookup:
            matched_lookup[domain] = []
        matched_lookup[domain].append({
            "fqdn": match.get("fqdn"),
            "tld": match.get("tld"),
            "first_seen": match.get("first_seen"),
            "last_seen": match.get("last_seen"),
            "dns_records": match.get("dns_records"),
            "metadata": match.get("metadata")
        })
    
    variations_response = []
    for variation in sorted(variations):
        is_matched = variation in matched_lookup
        entry = {
            "variation": variation,
            "is_original": variation == brand,
            "matched": is_matched,
            "match_count": len(matched_lookup.get(variation, []))
        }
        if is_matched:
            entry["matches"] = matched_lookup[variation]
        variations_response.append(entry)
    
    end_time = datetime.utcnow()
    processing_time = (end_time - start_time).total_seconds()
    
    return {
        "brand": request.brand_name,
        "brand_extracted": brand,
        "search_params": {
            "days_back": request.days_back or 7,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "algorithms": request.algorithms or ["all"],
            "tlds": request.tlds or ["all"]
        },
        "total_variations": len(variations),
        "matched_variations": len(matched_lookup),
        "total_matches": sum(len(v) for v in matched_lookup.values()),
        "algorithms_used": variation_result["algorithms_used"],
        "processing_time_seconds": processing_time,
        "variations": variations_response
    }


@search_router.post("/search/similarity")
async def search_similarity(request: SimilarityRequest):
    """
    Search for similar domains using SEPARATE algorithms.
    
    Each algorithm returns its own results independently:
    - **Levenshtein**: Edit distance (typos like 'gogle' → 'google')
    - **Jaro-Winkler**: Prefix-weighted similarity ('googel' → 'google')
    - **Homograph**: IDN/Unicode look-alike attacks ('gооgle' → 'google')
    
    **Each algorithm has its own threshold** which you can customize.
    """
    start_time = datetime.utcnow()
    
    logger.info(f"🔍 Similarity search: brand='{request.brand_name}', days_back={request.days_back or 7}")
    
    domain, tld = extract_brand_name(request.brand_name)
    brand = domain if domain else request.brand_name.lower().replace(".", "")
    
    now = datetime.utcnow()
    end_date = datetime(now.year, now.month, now.day) + timedelta(days=1)
    start_date = end_date - timedelta(days=request.days_back or 7)
    
    domains = await mongodb.scan_domains_for_similarity(
        brand=brand,
        start_date=start_date,
        end_date=end_date,
        tlds_filter=request.tlds,
        length_tolerance=3
    )
    
    lev_threshold = request.levenshtein_threshold or 0.70
    jw_threshold = request.jaro_winkler_threshold or 0.75
    
    results = {
        "levenshtein": string_similarity.levenshtein_search(
            brand=brand, domains=domains, min_similarity=lev_threshold, max_results=200
        ),
        "jaro_winkler": string_similarity.jaro_winkler_search(
            brand=brand, domains=domains, min_similarity=jw_threshold, max_results=200
        )
    }
    
    if request.homograph_enabled:
        results["homograph"] = string_similarity.homograph_search(
            brand=brand, domains=domains, min_substitutions=1, max_results=100
        )
    
    end_time = datetime.utcnow()
    processing_time = (end_time - start_time).total_seconds()
    
    return {
        "brand": request.brand_name,
        "brand_extracted": brand,
        "search_params": {
            "days_back": request.days_back or 7,
            "levenshtein_threshold": lev_threshold,
            "jaro_winkler_threshold": jw_threshold,
            "homograph_enabled": request.homograph_enabled,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "tlds": request.tlds or ["all"]
        },
        "domains_scanned": len(domains),
        "summary": {
            "levenshtein_matches": len(results.get("levenshtein", [])),
            "jaro_winkler_matches": len(results.get("jaro_winkler", [])),
            "homograph_matches": len(results.get("homograph", [])) if request.homograph_enabled else 0
        },
        "processing_time_seconds": processing_time,
        "results": results
    }


@search_router.post("/search/keyword")
async def search_keyword(request: KeywordRequest):
    """
    Search for domains CONTAINING a specific keyword.
    
    This is fast because it uses MongoDB regex search.
    
    Use cases:
    - Find all domains containing 'google' (e.g., google-login, mygoogle, googleshop)
    - Find brand mentions in newly registered domains
    - Detect keyword-based phishing attempts
    """
    start_time = datetime.utcnow()
    
    logger.info(f"🔍 Keyword search: keyword='{request.keyword}', days_back={request.days_back or 7}")
    
    if len(request.keyword) < 3:
        raise HTTPException(
            status_code=400,
            detail="Keyword must be at least 3 characters"
        )
    
    now = datetime.utcnow()
    end_date = datetime(now.year, now.month, now.day) + timedelta(days=1)
    start_date = end_date - timedelta(days=request.days_back or 7)
    
    matches = await mongodb.search_by_keyword(
        keyword=request.keyword,
        start_date=start_date,
        end_date=end_date,
        tlds_filter=request.tlds,
        limit=request.limit or 500
    )
    
    end_time = datetime.utcnow()
    processing_time = (end_time - start_time).total_seconds()
    
    return {
        "keyword": request.keyword,
        "search_params": {
            "days_back": request.days_back or 7,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "tlds": request.tlds or ["all"],
            "limit": request.limit or 500
        },
        "total_matches": len(matches),
        "processing_time_seconds": processing_time,
        "matches": matches
    }


@algorithms_router.get("/algorithms", response_model=List[AlgorithmInfo])
async def list_algorithms():
    """
    List all available algorithms for phishing detection.
    
    Includes both typosquatting and similarity algorithms.
    """
    algorithms = []
    
    typo_algos = typo_generator.get_available_algorithms()
    for name, desc in typo_algos.items():
        algorithms.append(AlgorithmInfo(
            name=name,
            category="typosquatting",
            description=desc
        ))
    
    similarity_algos = [
        {
            "name": "levenshtein",
            "category": "similarity",
            "description": "Edit distance (insertions, deletions, substitutions). Lower distance = more similar."
        },
        {
            "name": "jaro_winkler",
            "category": "similarity", 
            "description": "Similarity for short strings, favors matching prefixes. Higher score = more similar."
        },
        {
            "name": "homograph",
            "category": "detection",
            "description": "Detects IDN homograph attacks using similar-looking Unicode characters."
        }
    ]
    
    for algo in similarity_algos:
        algorithms.append(AlgorithmInfo(**algo))
    
    return algorithms
