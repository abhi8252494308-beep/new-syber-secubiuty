from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import select
from .config import settings
import uuid

# Use SQLite URL directly (already in async format)
DATABASE_URL = settings.DATABASE_URL

# SQLite doesn't support connection pooling, so we use NullPool
if DATABASE_URL.startswith("sqlite"):
    engine = create_async_engine(
        DATABASE_URL,
        echo=settings.DEBUG,
    )
else:
    # PostgreSQL/other databases
    engine = create_async_engine(
        DATABASE_URL,
        echo=settings.DEBUG,
        pool_size=20,
        max_overflow=10,
        pool_pre_ping=True,
    )

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Create default user for no-auth mode
    await _create_default_user()


async def _create_default_user():
    """Create a default user for no-auth mode"""
    from .models.user import User
    
    # Pre-computed bcrypt hash for "default123"
    DEFAULT_PASSWORD_HASH = "$2b$12$Wx6iC9nsN8ifjX7DU4XfNek/qK69aod20W634VcKnwT93is9PP.bq"
    
    async with AsyncSessionLocal() as db:
        # Check if default user exists
        result = await db.execute(
            select(User).where(User.email == "default@securesite-audit.local")
        )
        existing_user = result.scalar_one_or_none()
        
        if not existing_user:
            default_user = User(
                id=str(uuid.uuid4()),
                email="default@securesite-audit.local",
                hashed_password=DEFAULT_PASSWORD_HASH,
                full_name="Default User",
                is_active=True,
                is_verified=True,
            )
            db.add(default_user)
            await db.commit()
