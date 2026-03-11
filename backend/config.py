"""Application configuration classes for different environments."""

import os

# Optional: load .env file if python-dotenv is installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed – fall back to OS environment variables


class Config:
    """Base configuration."""

    SECRET_KEY: str = os.environ.get('SECRET_KEY', 'change-me-in-production')
    MONGO_URI: str = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/vulnguard')
    JWT_EXPIRY_HOURS: int = int(os.environ.get('JWT_EXPIRY_HOURS', '1'))
    ITEMS_PER_PAGE: int = int(os.environ.get('ITEMS_PER_PAGE', '10'))
    MAX_ITEMS_PER_PAGE: int = 100
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024  # 16 MB max request size


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG: bool = True


class TestingConfig(Config):
    """Testing configuration."""

    TESTING: bool = True
    MONGO_URI: str = os.environ.get(
        'TEST_MONGO_URI', 'mongodb://localhost:27017/vulnguard_test'
    )


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG: bool = False


config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
}
