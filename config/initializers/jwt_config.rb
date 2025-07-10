class JwtConfig
  include ActiveSupport::Configurable

  # JWT Algorithm
  config_accessor :algorithm, default: 'HS256'

  # Access Token Configuration
  config_accessor :access_token_secret, default: lambda {
    Rails.application.credentials.jwt_access_secret ||
      ENV['JWT_ACCESS_SECRET'] ||
      'default-access-secret-change-in-production'
  }
  config_accessor :access_token_expiration, default: 15.minutes

  # Refresh Token Configuration
  config_accessor :refresh_token_secret, default: lambda {
    Rails.application.credentials.jwt_refresh_secret ||
      ENV['JWT_REFRESH_SECRET'] ||
      'default-refresh-secret-change-in-production'
  }
  config_accessor :refresh_token_expiration, default: 7.days

  # Remember Me Configuration
  config_accessor :remember_me_expiration, default: 30.days
  config_accessor :allow_remember_me, default: true

  # Session Configuration
  config_accessor :session_cleanup_interval, default: 1.hour
  config_accessor :max_sessions_per_user, default: 10

  # Security Configuration
  config_accessor :require_secure_cookies, default: -> { Rails.env.production? }
  config_accessor :same_site_cookie_policy, default: :lax

  class << self
    # Resolve callable defaults
    def access_token_secret
      resolve_value(config.access_token_secret)
    end

    def refresh_token_secret
      resolve_value(config.refresh_token_secret)
    end

    def require_secure_cookies
      resolve_value(config.require_secure_cookies)
    end

    # Validation methods
    def valid_configuration?
      access_token_secret.present? &&
        refresh_token_secret.present? &&
        algorithm.present? &&
        access_token_expiration.present? &&
        refresh_token_expiration.present?
    end

    def validate_configuration!
      errors = []

      errors << 'access_token_secret is required' if access_token_secret.blank?
      errors << 'refresh_token_secret is required' if refresh_token_secret.blank?
      errors << 'algorithm is required' if algorithm.blank?
      errors << 'access_token_expiration must be positive' unless access_token_expiration&.positive?
      errors << 'refresh_token_expiration must be positive' unless refresh_token_expiration&.positive?

      if access_token_secret == refresh_token_secret
        errors << 'access_token_secret and refresh_token_secret should be different for security'
      end

      if Rails.env.production?
        if access_token_secret == 'default-access-secret-change-in-production'
          errors << 'Default access token secret detected in production - please configure a secure secret'
        end

        if refresh_token_secret == 'default-refresh-secret-change-in-production'
          errors << 'Default refresh token secret detected in production - please configure a secure secret'
        end
      end

      return unless errors.any?

      raise ConfigurationError, "JWT Configuration errors:\n#{errors.map { |e| "  - #{e}" }.join("\n")}"
    end

    # Configuration summary for debugging
    def configuration_summary
      {
        algorithm:,
        access_token_expiration:,
        refresh_token_expiration:,
        remember_me_expiration:,
        allow_remember_me:,
        session_cleanup_interval:,
        max_sessions_per_user:,
        require_secure_cookies:,
        same_site_cookie_policy:,
        access_token_secret_present: access_token_secret.present?,
        refresh_token_secret_present: refresh_token_secret.present?,
        secrets_are_different: access_token_secret != refresh_token_secret
      }
    end

    private

    def resolve_value(value)
      value.respond_to?(:call) ? value.call : value
    end
  end

  class ConfigurationError < StandardError; end
end

# Configure based on environment
JwtConfig.configure do |config|
  config.access_token_secret = Rails.application.credentials.jwt_access_secret
  config.refresh_token_secret = Rails.application.credentials.jwt_refresh_secret
  config.algorithm = 'HS256'

  case Rails.env
  when 'development'
    config.access_token_expiration = 1.hour
    config.refresh_token_expiration = 30.days
    config.remember_me_expiration = 90.days
    config.require_secure_cookies = false
    config.max_sessions_per_user = 20
  when 'production'
    config.access_token_expiration = 15.minutes
    config.refresh_token_expiration = 7.days
    config.remember_me_expiration = 30.days
    config.require_secure_cookies = true
    config.max_sessions_per_user = 5
  when 'test'
    config.access_token_secret = 'test-access-secret'
    config.refresh_token_secret = 'test-refresh-secret'
    config.access_token_expiration = 1.hour
    config.refresh_token_expiration = 1.day
    config.remember_me_expiration = 7.days
    config.require_secure_cookies = false
  end
end

# Validate configuration on startup
Rails.application.config.after_initialize do
  JwtConfig.validate_configuration!
  Rails.logger.info '✅ JWT Configuration validated successfully'

  if Rails.env.development?
    Rails.logger.debug 'JWT Configuration Summary:'
    JwtConfig.configuration_summary.each do |key, value|
      Rails.logger.debug "  #{key}: #{value}"
    end
  end
rescue JwtConfig::ConfigurationError => e
  Rails.logger.error "❌ #{e.message}"
  raise e if Rails.env.production?
end
