from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Set
import logging
import re

from app.config import settings

logger = logging.getLogger(__name__)


class MongoDB:
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None
    
    async def connect(self):
        """Connect to MongoDB."""
        logger.info(f"Connecting to MongoDB at {settings.mongodb_url}")
        self.client = AsyncIOMotorClient(settings.mongodb_url)
        self.db = self.client[settings.database_name]
        
        await self.client.admin.command("ping")
        logger.info(f"Connected to MongoDB database: {settings.database_name}")
    
    async def disconnect(self):
        """Disconnect from MongoDB."""
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")
    
    def get_collection_name(self, tld: str) -> str:
        """Get collection name for a TLD."""
        safe_tld = tld.lower().replace(".", "_").replace("-", "_")
        return f"{safe_tld}_tld"
    
    async def list_tld_collections(self) -> List[str]:
        """List all TLD collections in the database."""
        collections = await self.db.list_collection_names()
        tld_collections = [c for c in collections if c.endswith("_tld")]
        return tld_collections
    
    async def get_all_tlds(self) -> List[str]:
        """Get list of all TLDs from collection names."""
        collections = await self.list_tld_collections()
        return [c.replace("_tld", "").replace("_", ".") for c in collections]
    
    async def ensure_text_index(self, collection_name: str):
        """Ensure text index exists on domain field for faster text search."""
        collection = self.db[collection_name]
        try:
            await collection.create_index([("domain", "text")])
        except Exception as e:
            logger.debug(f"Text index may already exist: {e}")
    
    async def find_matching_domains(
        self,
        domain_variations: Set[str],
        start_date: datetime,
        end_date: datetime,
        tlds_filter: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Find domains matching any of the variations within the date range.
        """
        matches = []
        
        if tlds_filter:
            collections = [self.get_collection_name(tld) for tld in tlds_filter]
        else:
            collections = await self.list_tld_collections()
        
        variations_list = list(domain_variations)
        batch_size = settings.batch_size
        
        for collection_name in collections:
            collection = self.db[collection_name]
            tld_name = collection_name.replace("_tld", "").replace("_", ".")
            
            for i in range(0, len(variations_list), batch_size):
                batch = variations_list[i:i + batch_size]
                
                query = {
                    "domain": {"$in": batch},
                    "first_seen": {
                        "$gte": start_date,
                        "$lt": end_date
                    }
                }
                
                cursor = collection.find(query)
                
                async for doc in cursor:
                    doc["_id"] = str(doc["_id"])
                    doc["matched_tld"] = tld_name
                    matches.append(doc)
        
        return matches
    
    async def search_by_keyword(
        self,
        keyword: str,
        start_date: datetime,
        end_date: datetime,
        tlds_filter: Optional[List[str]] = None,
        limit: int = 500
    ) -> List[Dict[str, Any]]:
        """
        Search domains containing the keyword (case-insensitive).
        Uses MongoDB regex for substring matching.
        """
        matches = []
        
        if tlds_filter:
            collections = [self.get_collection_name(tld) for tld in tlds_filter]
        else:
            collections = await self.list_tld_collections()
        
        escaped_keyword = re.escape(keyword.lower())
        
        for collection_name in collections:
            if len(matches) >= limit:
                break
                
            collection = self.db[collection_name]
            tld_name = collection_name.replace("_tld", "").replace("_", ".")
            
            query = {
                "domain": {"$regex": escaped_keyword, "$options": "i"},
                "first_seen": {
                    "$gte": start_date,
                    "$lt": end_date
                }
            }
            
            cursor = collection.find(query).limit(limit - len(matches))
            
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                doc["tld"] = tld_name
                matches.append(doc)
        
        logger.info(f"Keyword search '{keyword}': found {len(matches)} matches")
        return matches
    
    async def scan_domains_for_similarity(
        self,
        brand: str,
        start_date: datetime,
        end_date: datetime,
        tlds_filter: Optional[List[str]] = None,
        length_tolerance: int = 3,
        limit_per_tld: int = 50000
    ) -> List[Dict[str, Any]]:
        """
        Scan domains within date range for similarity comparison.
        
        OPTIMIZED: Pre-filters by domain length to reduce computation.
        Only returns domains where |len(brand) - len(domain)| <= length_tolerance.
        """
        all_domains = []
        brand_len = len(brand)
        min_len = max(1, brand_len - length_tolerance)
        max_len = brand_len + length_tolerance
        
        if tlds_filter:
            collections = [self.get_collection_name(tld) for tld in tlds_filter]
        else:
            collections = await self.list_tld_collections()
        
        for collection_name in collections:
            collection = self.db[collection_name]
            tld_name = collection_name.replace("_tld", "").replace("_", ".")
            
            query = {
                "first_seen": {
                    "$gte": start_date,
                    "$lt": end_date
                },
                "$expr": {
                    "$and": [
                        {"$gte": [{"$strLenCP": "$domain"}, min_len]},
                        {"$lte": [{"$strLenCP": "$domain"}, max_len]}
                    ]
                }
            }
            
            cursor = collection.find(
                query,
                {"domain": 1, "fqdn": 1, "first_seen": 1, "last_seen": 1, "dns_records": 1}
            ).limit(limit_per_tld)
            
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                doc["tld"] = tld_name
                all_domains.append(doc)
        
        logger.info(
            f"Scanned {len(all_domains)} domains from {len(collections)} TLDs "
            f"(length filter: {min_len}-{max_len} chars for brand '{brand}')"
        )
        return all_domains
    
    async def search_domains_by_pattern(
        self,
        pattern: str,
        start_date: datetime,
        end_date: datetime,
        tlds_filter: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Search domains using a regex pattern within the date range.
        """
        matches = []
        
        if tlds_filter:
            collections = [self.get_collection_name(tld) for tld in tlds_filter]
        else:
            collections = await self.list_tld_collections()
        
        for collection_name in collections:
            if len(matches) >= limit:
                break
                
            collection = self.db[collection_name]
            tld_name = collection_name.replace("_tld", "").replace("_", ".")
            
            query = {
                "domain": {"$regex": pattern, "$options": "i"},
                "first_seen": {
                    "$gte": start_date,
                    "$lt": end_date
                }
            }
            
            cursor = collection.find(query).limit(limit - len(matches))
            
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                doc["matched_tld"] = tld_name
                matches.append(doc)
        
        return matches[:limit]


mongodb = MongoDB()
