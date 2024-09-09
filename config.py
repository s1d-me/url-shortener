# # config.py

# # Rate limits for different tiers
# FREE_TIER_RATE_LIMIT = "1 per day"
# PREMIUM_TIER_RATE_LIMIT = "2 per second, 50 per hour, 100 per day, 2000 per month, 20000 per year"
# ENTERPRISE_TIER_RATE_LIMIT = "5 per second, 100 per hour, 200 per day, 5000 per month, 50000 per year"
# ADMIN_TIER_RATE_LIMIT = "10 per second, 200 per hour, 500 per day, 10000 per month, 100000 per year"
# DEFAULT_RATE_LIMIT = "2 per day"

# config.py
DB_NAME = 'your_database_name'
DB_USER = 'your_database_user'
DB_PASSWORD = 'your_database_password'
DB_HOST = 'your_database_host'
DB_PORT = 'your_database_port'

# Rate limits for different tiers
ANON_RATE_LIMIT = "1 per 5 seconds, 5 per day"
FREE_TIER_RATE_LIMIT = "1 per 2 seconds, 20 per hour, 50 per day, 1000 per month, 10000 per year"
PREMIUM_TIER_RATE_LIMIT = "2 per second, 50 per hour, 100 per day, 2000 per month, 20000 per year"
ENTERPRISE_TIER_RATE_LIMIT = "5 per second, 100 per hour, 200 per day, 5000 per month, 50000 per year"
ADMIN_TIER_RATE_LIMIT = "10 per second, 200 per hour, 500 per day, 10000 per month, 100000 per year"


# config.py

FREE_TIER_API_TOKEN_LIMIT = 2
PREMIUM_TIER_API_TOKEN_LIMIT = 5
ENTERPRISE_TIER_API_TOKEN_LIMIT = 10
ADMIN_TIER_API_TOKEN_LIMIT = 20
