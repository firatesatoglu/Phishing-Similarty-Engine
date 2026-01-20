"""
String similarity algorithms for phishing detection.
Uses Levenshtein distance, Jaro-Winkler similarity, and Homograph detection.
Each algorithm returns separate results.
"""

from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
import logging

from strsimpy.levenshtein import Levenshtein
from strsimpy.jaro_winkler import JaroWinkler
from strsimpy.normalized_levenshtein import NormalizedLevenshtein

logger = logging.getLogger(__name__)


DEFAULT_LEVENSHTEIN_THRESHOLD = 0.70
DEFAULT_JARO_WINKLER_THRESHOLD = 0.75
DEFAULT_HOMOGRAPH_MIN_SUBS = 1  # Minimum substitutions to flag


class StringSimilarity:
    """
    String similarity calculator using multiple algorithms.
    
    Each algorithm returns SEPARATE results:
    - Levenshtein: Edit distance (insertions, deletions, substitutions)
    - Jaro-Winkler: Similarity for short strings, favors matching prefixes
    - Homograph: IDN homograph attack detection
    """
    
    def __init__(self):
        self.levenshtein = Levenshtein()
        self.normalized_levenshtein = NormalizedLevenshtein()
        self.jaro_winkler = JaroWinkler()
        
        self.homograph_map = {
            'a': ['а', 'ą', 'ä', 'à', 'á', 'â', 'ã', '@', '4', 'α'],
            'b': ['ḅ', 'ß', '6', '8', 'β'],
            'c': ['с', 'ç', '(', '¢', 'ċ'],
            'd': ['ԁ', 'ḍ', 'đ', 'ð'],
            'e': ['е', 'ė', 'ę', 'è', 'é', 'ê', 'ë', '3', '€', 'ε'],
            'g': ['ġ', 'ğ', '9', 'ģ'],
            'h': ['һ', 'ḥ', 'ħ'],
            'i': ['і', 'ı', 'ì', 'í', 'î', 'ï', '1', 'l', '!', '|', 'ι'],
            'j': ['ј', 'ĵ'],
            'k': ['κ', 'ḳ', 'ķ'],
            'l': ['ł', '1', 'i', '|', 'ι'],
            'm': ['rn', 'ṃ', 'м'],
            'n': ['ń', 'ñ', 'ṇ', 'η', 'п'],
            'o': ['о', 'ο', 'ö', 'ò', 'ó', 'ô', 'õ', '0', 'ø', 'θ'],
            'p': ['р', 'ρ', 'þ'],
            'q': ['ԛ', 'զ'],
            'r': ['г', 'ṛ', 'ŗ'],
            's': ['ѕ', 'ś', 'ş', '$', '5', 'ș'],
            't': ['т', 'ṭ', '7', '+', 'τ'],
            'u': ['υ', 'ü', 'ù', 'ú', 'û', 'μ'],
            'v': ['ν', 'ѵ', 'ư'],
            'w': ['ω', 'ẃ', 'ẁ', 'ŵ', 'vv', 'ш'],
            'x': ['х', 'χ', '×'],
            'y': ['у', 'ý', 'ÿ', 'γ'],
            'z': ['ź', 'ż', '2', 'ž'],
        }
    
    
    def levenshtein_search(
        self,
        brand: str,
        domains: List[Dict[str, Any]],
        min_similarity: float = DEFAULT_LEVENSHTEIN_THRESHOLD,
        max_results: int = 200
    ) -> List[Dict[str, Any]]:
        """
        Find similar domains using Levenshtein distance.
        
        Levenshtein measures the minimum number of single-character edits
        (insertions, deletions, substitutions) needed to change one string to another.
        """
        brand_lower = brand.lower()
        matches = []
        
        for doc in domains:
            domain_name = doc.get("domain", "").lower()
            if not domain_name:
                continue
            
            if brand_lower == domain_name:
                similarity = 1.0
                distance = 0
            else:
                distance = self.levenshtein.distance(brand_lower, domain_name)
                normalized = self.normalized_levenshtein.distance(brand_lower, domain_name)
                similarity = round(1.0 - normalized, 4)
            
            if similarity >= min_similarity:
                matches.append({
                    "domain": domain_name,
                    "fqdn": doc.get("fqdn"),
                    "tld": doc.get("tld"),
                    "first_seen": doc.get("first_seen"),
                    "last_seen": doc.get("last_seen"),
                    "dns_records": doc.get("dns_records"),
                    "levenshtein_distance": distance,
                    "similarity": similarity,
                    "is_exact": brand_lower == domain_name
                })
        
        matches.sort(key=lambda x: x["similarity"], reverse=True)
        return matches[:max_results]
    
    
    def jaro_winkler_search(
        self,
        brand: str,
        domains: List[Dict[str, Any]],
        min_similarity: float = DEFAULT_JARO_WINKLER_THRESHOLD,
        max_results: int = 200
    ) -> List[Dict[str, Any]]:
        """
        Find similar domains using Jaro-Winkler similarity.
        
        Jaro-Winkler is designed for short strings like names.
        It gives more weight to matching prefixes.
        """
        brand_lower = brand.lower()
        matches = []
        
        for doc in domains:
            domain_name = doc.get("domain", "").lower()
            if not domain_name:
                continue
            
            if brand_lower == domain_name:
                similarity = 1.0
            else:
                similarity = round(self.jaro_winkler.similarity(brand_lower, domain_name), 4)
            
            if similarity >= min_similarity:
                matches.append({
                    "domain": domain_name,
                    "fqdn": doc.get("fqdn"),
                    "tld": doc.get("tld"),
                    "first_seen": doc.get("first_seen"),
                    "last_seen": doc.get("last_seen"),
                    "dns_records": doc.get("dns_records"),
                    "similarity": similarity,
                    "is_exact": brand_lower == domain_name
                })
        
        matches.sort(key=lambda x: x["similarity"], reverse=True)
        return matches[:max_results]
    
    
    def homograph_search(
        self,
        brand: str,
        domains: List[Dict[str, Any]],
        min_substitutions: int = DEFAULT_HOMOGRAPH_MIN_SUBS,
        max_results: int = 200
    ) -> List[Dict[str, Any]]:
        """
        Find domains using homograph/IDN attack patterns.
        
        Detects character substitutions using look-alike characters
        (e.g., 'о' (cyrillic) instead of 'o' (latin)).
        """
        brand_lower = brand.lower()
        matches = []
        
        for doc in domains:
            domain_name = doc.get("domain", "").lower()
            if not domain_name:
                continue
            
            result = self._detect_homograph(brand_lower, domain_name)
            
            if result["is_homograph"] and result["substitution_count"] >= min_substitutions:
                matches.append({
                    "domain": domain_name,
                    "fqdn": doc.get("fqdn"),
                    "tld": doc.get("tld"),
                    "first_seen": doc.get("first_seen"),
                    "last_seen": doc.get("last_seen"),
                    "dns_records": doc.get("dns_records"),
                    "is_homograph": True,
                    "substitution_count": result["substitution_count"],
                    "substitutions": result["substitutions"],
                    "risk_level": self._calculate_homograph_risk(result["substitution_count"], len(brand_lower))
                })
        
        matches.sort(key=lambda x: x["substitution_count"])
        return matches[:max_results]
    
    def _detect_homograph(self, brand: str, domain: str) -> Dict[str, Any]:
        """Internal method to detect homograph substitutions."""
        substitutions = []
        
        if len(brand) != len(domain):
            if abs(len(brand) - len(domain)) <= 2:
                pass
            return {"is_homograph": False, "substitutions": [], "substitution_count": 0}
        
        for i, (b_char, d_char) in enumerate(zip(brand, domain)):
            if b_char != d_char:
                if b_char in self.homograph_map and d_char in self.homograph_map[b_char]:
                    substitutions.append({
                        "position": i,
                        "original": b_char,
                        "substitute": d_char
                    })
                else:
                    return {"is_homograph": False, "substitutions": [], "substitution_count": 0}
        
        is_homograph = len(substitutions) > 0
        return {
            "is_homograph": is_homograph,
            "substitutions": substitutions,
            "substitution_count": len(substitutions)
        }
    
    def _calculate_homograph_risk(self, sub_count: int, brand_length: int) -> str:
        """Calculate risk level based on substitution density."""
        if sub_count == 1:
            return "critical"  # Single substitution = very deceptive
        elif sub_count <= 2:
            return "high"
        elif sub_count <= brand_length // 2:
            return "medium"
        else:
            return "low"
    
    
    def combined_search(
        self,
        brand: str,
        domains: List[Dict[str, Any]],
        levenshtein_threshold: float = DEFAULT_LEVENSHTEIN_THRESHOLD,
        jaro_winkler_threshold: float = DEFAULT_JARO_WINKLER_THRESHOLD,
        max_results: int = 500
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run all algorithms and return separate results for each.
        
        Returns:
            Dict with keys: 'levenshtein', 'jaro_winkler', 'homograph'
        """
        return {
            "levenshtein": self.levenshtein_search(brand, domains, levenshtein_threshold, max_results),
            "jaro_winkler": self.jaro_winkler_search(brand, domains, jaro_winkler_threshold, max_results),
            "homograph": self.homograph_search(brand, domains, 1, max_results)
        }


string_similarity = StringSimilarity()
