from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional, Dict, Any, List
from datetime import datetime
from pymongo import ASCENDING, DESCENDING, TEXT
import logging

logger = logging.getLogger(__name__)


class MongoDBService:
    """MongoDB service for storing audit results and reports"""
    
    def __init__(self, uri: str = "mongodb://localhost:27017", db_name: str = "securesite_audit"):
        self.uri = uri
        self.db_name = db_name
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
    
    async def connect(self):
        """Connect to MongoDB"""
        try:
            self.client = AsyncIOMotorClient(self.uri)
            self.db = self.client[self.db_name]
            await self._create_indexes()
            logger.info(f"Connected to MongoDB: {self.db_name}")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    async def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            logger.info("MongoDB connection closed")
    
    async def _create_indexes(self):
        """Create necessary indexes"""
        try:
            # Audit results collection
            await self.db.audit_results.create_index([("audit_id", ASCENDING)], unique=True)
            await self.db.audit_results.create_index([("domain", ASCENDING)])
            await self.db.audit_results.create_index([("created_at", DESCENDING)])
            await self.db.audit_results.create_index([("risk_score", ASCENDING)])
            
            # Domains collection
            await self.db.domains.create_index([("domain", ASCENDING)], unique=True)
            await self.db.domains.create_index([("created_at", DESCENDING)])
            
            # Reports collection
            await self.db.reports.create_index([("audit_id", ASCENDING)])
            await self.db.reports.create_index([("generated_at", DESCENDING)])
            
            logger.info("MongoDB indexes created")
        except Exception as e:
            logger.error(f"Failed to create indexes: {e}")
    
    async def save_audit_result(self, result: Dict[str, Any]) -> str:
        """Save audit result to MongoDB"""
        try:
            result["created_at"] = datetime.utcnow()
            result["updated_at"] = datetime.utcnow()
            
            # Upsert based on audit_id
            await self.db.audit_results.update_one(
                {"audit_id": result["audit_id"]},
                {"$set": result},
                upsert=True
            )
            return result["audit_id"]
        except Exception as e:
            logger.error(f"Failed to save audit result: {e}")
            raise
    
    async def get_audit_result(self, audit_id: str) -> Optional[Dict[str, Any]]:
        """Get audit result by ID"""
        try:
            return await self.db.audit_results.find_one({"audit_id": audit_id})
        except Exception as e:
            logger.error(f"Failed to get audit result: {e}")
            return None
    
    async def get_audit_results_by_domain(self, domain: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get audit results for a domain"""
        try:
            cursor = self.db.audit_results.find({"domain": domain}).sort("created_at", DESCENDING).limit(limit)
            return await cursor.to_list(length=limit)
        except Exception as e:
            logger.error(f"Failed to get audit results by domain: {e}")
            return []
    
    async def get_recent_audits(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get most recent audit results"""
        try:
            cursor = self.db.audit_results.find().sort("created_at", DESCENDING).limit(limit)
            return await cursor.to_list(length=limit)
        except Exception as e:
            logger.error(f"Failed to get recent audits: {e}")
            return []
    
    async def get_audits_by_risk_score(self, min_score: int = 0, max_score: int = 100, limit: int = 50) -> List[Dict[str, Any]]:
        """Get audits filtered by risk score"""
        try:
            cursor = self.db.audit_results.find({
                "risk_score": {"$gte": min_score, "$lte": max_score}
            }).sort("risk_score", DESCENDING).limit(limit)
            return await cursor.to_list(length=limit)
        except Exception as e:
            logger.error(f"Failed to get audits by risk score: {e}")
            return []
    
    async def save_domain(self, domain_data: Dict[str, Any]) -> str:
        """Save or update domain"""
        try:
            domain_data["updated_at"] = datetime.utcnow()
            if "created_at" not in domain_data:
                domain_data["created_at"] = datetime.utcnow()
            
            await self.db.domains.update_one(
                {"domain": domain_data["domain"]},
                {"$set": domain_data},
                upsert=True
            )
            return domain_data["domain"]
        except Exception as e:
            logger.error(f"Failed to save domain: {e}")
            raise
    
    async def get_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get domain by name"""
        try:
            return await self.db.domains.find_one({"domain": domain})
        except Exception as e:
            logger.error(f"Failed to get domain: {e}")
            return None
    
    async def get_all_domains(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all domains"""
        try:
            cursor = self.db.domains.find().sort("created_at", DESCENDING).limit(limit)
            return await cursor.to_list(length=limit)
        except Exception as e:
            logger.error(f"Failed to get domains: {e}")
            return []
    
    async def save_report(self, report_data: Dict[str, Any]) -> str:
        """Save generated report"""
        try:
            report_data["generated_at"] = datetime.utcnow()
            result = await self.db.reports.insert_one(report_data)
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            raise
    
    async def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get report by ID"""
        try:
            from bson import ObjectId
            return await self.db.reports.find_one({"_id": ObjectId(report_id)})
        except Exception as e:
            logger.error(f"Failed to get report: {e}")
            return None
    
    async def get_reports_by_audit(self, audit_id: str) -> List[Dict[str, Any]]:
        """Get all reports for an audit"""
        try:
            cursor = self.db.reports.find({"audit_id": audit_id}).sort("generated_at", DESCENDING)
            return await cursor.to_list(length=100)
        except Exception as e:
            logger.error(f"Failed to get reports by audit: {e}")
            return []
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        try:
            total_audits = await self.db.audit_results.count_documents({})
            
            # Risk score distribution
            pipeline = [
                {"$group": {"_id": "$risk_score", "count": {"$sum": 1}}},
                {"$sort": {"_id": 1}}
            ]
            risk_distribution = await self.db.audit_results.aggregate(pipeline).to_list(length=100)
            
            # Average scores
            pipeline = [
                {"$group": {
                    "_id": None,
                    "avg_risk": {"$avg": "$risk_score"},
                    "avg_score": {"$avg": "$overall_score"},
                    "min_risk": {"$min": "$risk_score"},
                    "max_risk": {"$max": "$risk_score"},
                }}
            ]
            avg_scores = await self.db.audit_results.aggregate(pipeline).to_list(length=1)
            
            # Top vulnerabilities
            pipeline = [
                {"$unwind": "$sslabs.vulnerabilities"},
                {"$group": {"_id": "$sslabs.vulnerabilities.name", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": 10}
            ]
            top_vulns = await self.db.audit_results.aggregate(pipeline).to_list(length=10)
            
            return {
                "total_audits": total_audits,
                "risk_distribution": risk_distribution,
                "average_scores": avg_scores[0] if avg_scores else {},
                "top_vulnerabilities": top_vulns,
            }
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}


# Global instance
mongodb_service: Optional[MongoDBService] = None


async def get_mongodb_service() -> MongoDBService:
    """Get MongoDB service instance"""
    global mongodb_service
    if mongodb_service is None:
        from ..config import settings
        mongodb_service = MongoDBService(
            uri=settings.MONGODB_URI,
            db_name=settings.MONGODB_DB_NAME
        )
        await mongodb_service.connect()
    return mongodb_service