module JwtRefreshAccessAuthentication
  extend ActiveSupport::Concern

  included do
    include ActionController::Cookies

    before_action :set_current_request_details
    before_action :restore_current_session, if: :refresh_token_present?
  end

  private

  def authenticate_request
    token = extract_token_from_header
    return render_unauthorized unless token

    begin
      decoded_token = JWT.decode(token, JwtConfig.access_token_secret, true, { algorithm: JwtConfig.algorithm })
      payload = decoded_token[0]

      user = find_user(payload['user_id'])
      return render_unauthorized unless user

      Current.user = user

      # If there's a session_token in the payload, try to find the session
      if payload['session_token'].present?
        session = Session.find_by(uuid: payload['session_token'], user:)
        Current.session = session if session&.active?
      end
    rescue JWT::DecodeError, JWT::ExpiredSignature => e
      Rails.logger.warn "JWT Authentication failed: #{e.message}"
      render_unauthorized
    end
  end

  def set_current_request_details
    Current.user_agent = request.user_agent
    Current.ip_address = request.remote_ip
    Current.request_id = request.uuid
  end

  def restore_current_session
    refresh_token = cookies[:refreshToken]
    return unless refresh_token

    begin
      decoded_token = JWT.decode(refresh_token, JwtConfig.refresh_token_secret, true,
                                 { algorithm: JwtConfig.algorithm })
      payload = decoded_token[0]

      return unless payload['type'] == 'refresh'
      return unless payload['session_token'].present?

      session = Session.find_by(uuid: payload['session_token'])
      if session&.active?
        Current.session = session
        Current.user = session.user
      end
    rescue JWT::DecodeError, JWT::ExpiredSignature
      # Silently fail - this is just for session restoration
    end
  end

  def refresh_token_present? = cookies[:refreshToken].present?

  def extract_token_from_header
    header = request.headers['Authorization']
    return nil unless header

    header.split(' ').last if header.match(/^Bearer /)
  end

  def generate_access_token(user:, session: nil)
    now = Time.current
    expires_at = JwtConfig.access_token_expiration.from_now
    payload = { user_id: user.uuid, exp: expires_at.to_i, iat: now.to_i }

    # Include session token if session exists
    payload[:session_token] = session.uuid if session

    log_token_generation(type: 'access', user_id: user.uuid, issued_at: now, expires_at:,
                         expires_in_seconds: JwtConfig.access_token_expiration.to_i)

    JWT.encode(payload, JwtConfig.access_token_secret, JwtConfig.algorithm)
  end

  def generate_refresh_token(user:, session:)
    now = Time.current

    expires_at = session.expires_at
    payload = {
      user_id: user.uuid,
      session_token: session.uuid,
      exp: expires_at.to_i,
      iat: now.to_i,
      type: 'refresh'
    }

    expires_in_seconds = session.remember_me? ? JwtConfig.remember_me_expiration.to_i : JwtConfig.refresh_token_expiration.to_i
    token = JWT.encode(payload, JwtConfig.refresh_token_secret, JwtConfig.algorithm)

    log_token_generation(type: 'refresh', user_id: user.uuid, issued_at: now, expires_at:, expires_in_seconds:, token:)

    token
  end

  def set_refresh_token_cookie(refresh_token, remember_me: false)
    expiration_time = remember_me ? JwtConfig.remember_me_expiration : JwtConfig.refresh_token_expiration
    expires = expiration_time.from_now

    response.set_cookie(:refreshToken, {
                          value: refresh_token,
                          expires:,
                          httponly: true,
                          secure: Rails.env.production?,
                          same_site: :lax,
                          path: '/'
                        })

    Rails.logger.info "Setting refreshToken cookie expires at: #{expires} (remember_me: #{remember_me})"
  end

  def clear_refresh_token_cookie = cookies.delete(:refreshToken)

  def handle_token_refresh
    refresh_token = cookies[:refreshToken]

    return render_unauthorized unless refresh_token

    begin
      decoded_token = JWT.decode(refresh_token, JwtConfig.refresh_token_secret, true,
                                 { algorithm: JwtConfig.algorithm })
      payload = decoded_token[0]

      # Verify it's a refresh token
      return render_unauthorized unless payload['type'] == 'refresh'
      return render_unauthorized unless payload['session_token'].present?

      # Find the session
      session = Session.find_by(uuid: payload['session_token'])

      return render_unauthorized unless Current.session == session && session.active?

      # Update session activity with remember_me consideration
      expiration_time = session.remember_me? ? JwtConfig.remember_me_expiration : JwtConfig.refresh_token_expiration

      session.update!(
        last_accessed_at: Time.current,
        user_agent: Current.user_agent,
        ip_address: Current.ip_address,
        expires_at: expiration_time.from_now
      )

      # Generate new tokens
      new_access_token = generate_access_token(user: Current.user, session: Current.session)
      new_refresh_token = generate_refresh_token(user: Current.user, session: Current.session)

      # Update cookie with new refresh token
      set_refresh_token_cookie(new_refresh_token, remember_me: session.remember_me?)

      {
        access_token: new_access_token,
        expires_in: JwtConfig.access_token_expiration.to_i,
        user: Current.user
      }
    rescue JWT::DecodeError, JWT::ExpiredSignature => e
      Rails.logger.warn "Refresh token validation failed: #{e.message}"
      render_unauthorized
      nil
    end
  end

  def logout_current_session
    if Current.session
      Current.session.update!(revoked_at: Time.current)
      Current.session = nil
    end

    Current.user = nil
    clear_refresh_token_cookie
  end

  def render_unauthorized
    render_error('Unauthorized', code: 'unauthorized', status: :unauthorized)
  end

  # Current user/session getters for compatibility
  def current_user = Current.user
  def current_session = Current.session

  protected

  # If you don't care about exposing primary keys and don't want to have a uuid
  # column on your users table, you could modify the code so that it does
  # lookups by id instead.
  def find_user(uuid) = User.find_by(uuid:)

  private

  # Great for debugging if you need to customize your solution.
  def log_token_generation(type:, user_id:, issued_at:, expires_at:, expires_in_seconds:, token: nil)
    Rails.logger.info "🎫 Generating #{type} token:"
    Rails.logger.info "  - User ID: #{user_id}"
    Rails.logger.info "  - Issued at: #{issued_at}"
    Rails.logger.info "  - Expires at: #{expires_at}"
    Rails.logger.info "  - Expires in: #{expires_in_seconds} seconds"
    Rails.logger.info "  - Session: #{Current.session&.uuid}" if Current.session
    Rails.logger.info "  - Token: #{token[0..20]}..." if token && type == 'refresh'
  end
end
