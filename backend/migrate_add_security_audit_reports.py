"""
Migration script to add SecurityAuditReport table
"""
from database import get_db, engine
from models import SecurityAuditReport, Base
import logging

def migrate_add_security_audit_reports():
    """Add SecurityAuditReport table to database"""
    try:
        logger = logging.getLogger(__name__)
        logger.info("Creating SecurityAuditReport table...")
        
        # Create the table
        SecurityAuditReport.__table__.create(engine, checkfirst=True)
        
        logger.info("SecurityAuditReport table created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error creating SecurityAuditReport table: {e}")
        return False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    migrate_add_security_audit_reports()
