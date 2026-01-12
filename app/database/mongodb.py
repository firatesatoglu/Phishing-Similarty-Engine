from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Set
import logging

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
        
        # Test connection
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
    
    async def find_matching_domains(
        self,
        domain_variations: Set[str],
        start_date: datetime,
        end_date: datetime,
        tlds_filter: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Find domains matching any of the variations within the date range.
        
        Args:
            domain_variations: Set of domain names to search for (without TLD)
            start_date: Start of date range
            end_date: End of date range
            tlds_filter: Optional list of TLDs to search in
        
        Returns:
            List of matching domain documents
        """
        matches = []
        
        # Get collections to query
        if tlds_filter:
            collections = [self.get_collection_name(tld) for tld in tlds_filter]
        else:
            collections = await self.list_tld_collections()
        
        # Convert variations to list for query
        variations_list = list(domain_variations)
        
        # Batch the variations to avoid query size limits
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
        
        This is useful for finding domains that contain a specific string.
        """
        matches = []
        
        # Get collections to query
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
    
    async def scan_domains_for_similarity(
        self,
        start_date: datetime,
        end_date: datetime,
        tlds_filter: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Scan ALL domains within date range for similarity comparison.
        No limits - returns everything in the date range.
        """
        all_domains = []
        
        # Get collections to query
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
                }
            }
            
            # Only fetch essential fields for performance
            cursor = collection.find(
                query,
                {"domain": 1, "fqdn": 1, "first_seen": 1, "last_seen": 1, "dns_records": 1}
            )
            
            async for doc in cursor:
                doc["_id"] = str(doc["_id"])
                doc["tld"] = tld_name
                all_domains.append(doc)
        
        logger.info(f"Scanned {len(all_domains)} domains from {len(collections)} TLDs")
        return all_domains


# Singleton instance
mongodb = MongoDB()
