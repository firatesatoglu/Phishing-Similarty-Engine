from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Set
import logging
import tldextract

from app.database.mongodb import mongodb
from app.services.typosquatting import typo_generator
from app.config import settings

logger = logging.getLogger(__name__)


class SimilarityService:
    """Service for finding similar domains (potential phishing)."""
    
    def _extract_brand_name(self, brand_input: str) -> str:
        """
        Extract just the brand/domain name from input.
        Handles both 'google' and 'google.com' inputs.
        """
        extracted = tldextract.extract(brand_input)
        if extracted.domain:
            return extracted.domain.lower()
        return brand_input.lower().replace(".", "")
    
    def get_date_range(
        self,
        days_back: Optional[int] = None
    ) -> tuple[datetime, datetime]:
        """Calculate date range based on days_back parameter."""
        now = datetime.utcnow()
        today_start = datetime(now.year, now.month, now.day)
        
        days = days_back if days_back is not None else settings.default_days_back
        start = today_start - timedelta(days=days)
        
        return start, today_start
    
    async def search_similar_domains(
        self,
        brand_name: str,
        days_back: Optional[int] = None,
        algorithms: Optional[List[str]] = None,
        tlds: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Search for domains similar to the brand name in recently registered domains.
        
        Args:
            brand_name: The brand/domain to search for (e.g., "google.com" or "google")
            days_back: Number of days back to search (default: 1)
            algorithms: Typosquatting algorithms to use (default: all)
            tlds: TLDs to search in (default: all)
        
        Returns:
            Dict with matches and metadata.
        """
        start_time = datetime.utcnow()
        
        brand = self._extract_brand_name(brand_name)
        
        start_date, end_date = self.get_date_range(days_back)
        
        logger.info(f"Generating variations for brand: {brand}")
        variation_result = typo_generator.generate_variations(
            domain=brand,
            algorithms=algorithms,
            limit=settings.max_variations
        )
        
        variations = set(variation_result["variations"])
        
        variations.add(brand)
        
        logger.info(f"Generated {len(variations)} variations")
        
        logger.info(f"Searching in database for matches...")
        matches = await mongodb.find_matching_domains(
            domain_variations=variations,
            start_date=start_date,
            end_date=end_date,
            tlds_filter=tlds
        )
        
        enriched_matches = []
        
        for match in matches:
            matched_domain = match.get("domain", "").lower()
            
            matched_algos = []
            for algo, count in variation_result["variations_by_algorithm"].items():
                if matched_domain in variations:
                    matched_algos.append(algo)
            
            if matched_domain == brand:
                match_type = "exact"
            else:
                match_type = "typosquat"
            
            enriched_matches.append({
                "domain": match.get("domain"),
                "fqdn": match.get("fqdn"),
                "tld": match.get("tld"),
                "first_seen": match.get("first_seen"),
                "last_seen": match.get("last_seen"),
                "dns_records": match.get("dns_records"),
                "whois": match.get("whois"),
                "match_type": match_type,
                "matched_algorithms": matched_algos if matched_algos else ["unknown"],
                "metadata": match.get("metadata")
            })
        
        enriched_matches.sort(
            key=lambda x: x.get("first_seen", datetime.min), 
            reverse=True
        )
        
        end_time = datetime.utcnow()
        processing_time = (end_time - start_time).total_seconds()
        
        return {
            "brand": brand_name,
            "brand_extracted": brand,
            "search_params": {
                "days_back": days_back or settings.default_days_back,
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "algorithms": algorithms or ["all"],
                "tlds": tlds or ["all"]
            },
            "variations_generated": len(variations),
            "algorithms_used": variation_result["algorithms_used"],
            "total_matches": len(enriched_matches),
            "processing_time_seconds": processing_time,
            "matches": enriched_matches
        }
    
    def get_available_algorithms(self) -> Dict[str, str]:
        """Get list of available algorithms."""
        return typo_generator.get_available_algorithms()
    
    async def get_available_tlds(self) -> List[str]:
        """Get list of available TLDs in database."""
        return await mongodb.get_all_tlds()


similarity_service = SimilarityService()
