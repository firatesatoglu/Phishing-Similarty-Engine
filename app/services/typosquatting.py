"""
Typosquatting wrapper for ail-typo-squatting library.
Generates domain name variations using various algorithms.
"""

from typing import List, Set, Dict, Any, Optional
import logging
import math

try:
    from ail_typo_squatting import (
        runAll,
        omission,
        repetition,
        replacement,
        doubleReplacement,
        changeOrder,
        addition,
        missingDot,
        stripDash,
        vowelSwap,
        addDash,
        homoglyph,
        commonMisspelling,
        homophones,
        wrongTld,
        wrongSld,
        addTld,
        subdomain,
        singularPluralize,
        changeDotDash,
        addDynamicDns,
        numeralSwap,
    )
    AIL_AVAILABLE = True
except ImportError:
    AIL_AVAILABLE = False
    logging.warning("ail-typo-squatting not available, using fallback implementations")

import tldextract

logger = logging.getLogger(__name__)


ALGORITHMS = {
    "omission": "Leave out a letter (google → gogle)",
    "repetition": "Repeat a character (google → gooogle)",
    "replacement": "Replace a character (google → goagle)",
    "double_replacement": "Replace two characters",
    "change_order": "Swap adjacent letters (google → ogogle)",
    "addition": "Add a character (google → googles)",
    "missing_dot": "Remove a dot from subdomain",
    "strip_dash": "Remove a dash",
    "vowel_swap": "Swap vowels (google → guugle)",
    "add_dash": "Add a dash",
    "homoglyph": "Use similar-looking characters (google → g00gle)",
    "common_misspelling": "Common misspellings",
    "homophones": "Words that sound the same",
    "wrong_tld": "Different TLD",
    "subdomain": "Add subdomain dots",
    "singular_pluralize": "Add/remove 's'",
    "numeral_swap": "Swap numbers and letters (one → 1)",
}


class TypoSquattingGenerator:
    """Generates typosquatting variations for domain names."""
    
    def __init__(self):
        self.ail_available = AIL_AVAILABLE
    
    def get_available_algorithms(self) -> Dict[str, str]:
        """Get list of available algorithms with descriptions."""
        return ALGORITHMS.copy()
    
    def _extract_domain_parts(self, domain: str) -> tuple[str, str]:
        """
        Extract the domain name and TLD from a full domain.
        Returns (domain_without_tld, tld)
        Always returns a TLD (defaults to 'com') for ail library compatibility.
        """
        extracted = tldextract.extract(domain)
        
        if extracted.suffix:
            domain_name = extracted.domain
            if extracted.subdomain:
                domain_name = f"{extracted.subdomain}.{extracted.domain}"
            tld = extracted.suffix
        else:
            domain_name = domain.replace(".", "")
            tld = "com"
        
        return domain_name, tld
    
    def generate_variations(
        self,
        domain: str,
        algorithms: Optional[List[str]] = None,
        limit: int = 10000
    ) -> Dict[str, Any]:
        """
        Generate typosquatting variations for a domain.
        
        Args:
            domain: The domain name (e.g., "google.com" or just "google")
            algorithms: List of algorithms to use. None or ["all"] means use all.
            limit: Maximum number of variations to generate.
        
        Returns:
            Dict with variations and metadata.
        """
        domain_name, original_tld = self._extract_domain_parts(domain)
        
        use_all = algorithms is None or "all" in algorithms or len(algorithms) == 0
        
        variations = set()
        algo_results = {}
        
        if self.ail_available:
            variations, algo_results = self._generate_with_ail(
                domain_name, original_tld, algorithms, use_all, limit
            )
        else:
            variations, algo_results = self._generate_fallback(
                domain_name, algorithms, use_all, limit
            )
        
        if len(variations) > limit:
            variations = set(list(variations)[:limit])
        
        return {
            "original_domain": domain,
            "domain_name": domain_name,
            "original_tld": original_tld,
            "total_variations": len(variations),
            "variations": list(variations),
            "algorithms_used": list(algo_results.keys()),
            "variations_by_algorithm": {k: len(v) for k, v in algo_results.items()}
        }
    
    def _generate_with_ail(
        self,
        domain_name: str,
        tld: str,
        algorithms: Optional[List[str]],
        use_all: bool,
        limit: int
    ) -> tuple[Set[str], Dict[str, List[str]]]:
        """Generate variations using ail-typo-squatting library."""
        
        full_domain = f"{domain_name}.{tld}" if tld else f"{domain_name}.com"
        
        variations = set()
        algo_results = {}
        
        algo_map = {
            "omission": omission,
            "repetition": repetition,
            "replacement": replacement,
            "double_replacement": doubleReplacement,
            "change_order": changeOrder,
            "addition": addition,
            "vowel_swap": vowelSwap,
            "add_dash": addDash,
            "homoglyph": homoglyph,
            "subdomain": subdomain,
            "singular_pluralize": singularPluralize,
            "numeral_swap": numeralSwap,
        }
        
        for algo_name, algo_func in algo_map.items():
            if not use_all and algorithms and algo_name not in algorithms:
                continue
            
            try:
                result = []
                result = algo_func(
                    domain=full_domain,
                    resultList=result,
                    verbose=False,
                    limit=limit,
                    givevariations=False,
                    keeporiginal=False
                )
                
                extracted = []
                for var in result:
                    ext = tldextract.extract(var)
                    if ext.domain:
                        extracted.append(ext.domain.lower())
                
                algo_results[algo_name] = extracted
                variations.update(extracted)
                
            except SystemExit:
                logger.debug(f"Algorithm {algo_name} failed with SystemExit (invalid domain)")
            except Exception as e:
                logger.debug(f"Algorithm {algo_name} failed: {str(e)}")
        
        return variations, algo_results
    
    def _generate_fallback(
        self,
        domain_name: str,
        algorithms: Optional[List[str]],
        use_all: bool,
        limit: int
    ) -> tuple[Set[str], Dict[str, List[str]]]:
        """Fallback variation generation without ail-typo-squatting."""
        
        variations = set()
        algo_results = {}
        
        if use_all or (algorithms and "omission" in algorithms):
            omissions = [
                domain_name[:i] + domain_name[i+1:]
                for i in range(len(domain_name))
            ]
            algo_results["omission"] = omissions
            variations.update(omissions)
        
        if use_all or (algorithms and "repetition" in algorithms):
            repetitions = [
                domain_name[:i] + domain_name[i] + domain_name[i:]
                for i in range(len(domain_name))
            ]
            algo_results["repetition"] = repetitions
            variations.update(repetitions)
        
        if use_all or (algorithms and "homoglyph" in algorithms):
            homoglyphs_map = {
                'a': ['4', '@'],
                'e': ['3'],
                'i': ['1', 'l'],
                'o': ['0'],
                's': ['5', '$'],
                'l': ['1', 'i'],
                'g': ['9'],
                't': ['7'],
            }
            
            homoglyph_vars = []
            for i, char in enumerate(domain_name.lower()):
                if char in homoglyphs_map:
                    for replacement in homoglyphs_map[char]:
                        homoglyph_vars.append(
                            domain_name[:i] + replacement + domain_name[i+1:]
                        )
            
            algo_results["homoglyph"] = homoglyph_vars
            variations.update(homoglyph_vars)
        
        if use_all or (algorithms and "addition" in algorithms):
            additions = []
            chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
            for i in range(len(domain_name) + 1):
                for char in 'aeiou':  # Just vowels to limit
                    additions.append(domain_name[:i] + char + domain_name[i:])
            algo_results["addition"] = additions[:limit]
            variations.update(additions[:limit])
        
        return variations, algo_results


typo_generator = TypoSquattingGenerator()
