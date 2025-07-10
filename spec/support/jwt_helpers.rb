module JwtHelpers
  def create_access_token(user_id:, session_token: nil, expired: false)
    exp_time = expired ? 1.hour.ago : 1.hour.from_now

    payload = {
      user_id:,
      exp: exp_time.to_i,
      iat: Time.current.to_i
    }
    payload[:session_token] = session_token if session_token

    JWT.encode(payload, JwtConfig.access_token_secret, JwtConfig.algorithm)
  end

  def create_refresh_token(user_id:, session_token:, expired: false)
    exp_time = expired ? 1.hour.ago : 6.days.from_now

    payload = {
      user_id:,
      session_token:,
      exp: exp_time.to_i,
      iat: Time.current.to_i,
      type: 'refresh'
    }

    JWT.encode(payload, JwtConfig.refresh_token_secret, JwtConfig.algorithm)
  end

  def parsed_response = @parsed_response ||= JSON.parse(response.body)
end

RSpec.configure do |config|
  config.include JwtHelpers, type: :controller
  config.include JwtHelpers, type: :request
end
