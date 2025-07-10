class SessionsController < ApplicationController
  skip_before_action :authenticate_request, only: [
    :create,
    # The update action relies on the presense of the
    # refresh token cookie for authentication, not the
    # access token so it handles it's own authentication
    # from inside handle_token_refresh.
    :update
  ]

  # POST /sessions (login)
  def create
    user = authenticate_user(session_params[:email], session_params[:password])

    if user
      # This block is very similar to the one in registrations#create
      # and can be extracted into a service class once this code is
      # sucessfully integrated into your app.

      remember_me = [true, 'true'].include?(session_params[:remember_me])

      # Create a new session for this login
      session = user.create_session!(remember_me:)

      # Set current context
      Current.user = user
      Current.session = session

      # Generate tokens
      access_token = generate_access_token(user:, session:)
      refresh_token = generate_refresh_token(user:, session:)

      # Set refresh token cookie with appropriate expiration
      set_refresh_token_cookie(refresh_token, remember_me:)

      render_success({
                       access_token:,
                       expires_in: JwtConfig.access_token_expiration.to_i,
                       user: serialize_user(user),
                       session: serialize_session(session)
                     }, status: :created)
    else
      render_error('Invalid credentials', code: 'invalid_credentials', status: :unauthorized)
    end
  end

  # PATCH /sessions (refresh)
  def update
    result = handle_token_refresh

    # Error handling is done in handle_token_refresh
    return unless result
    return unless result['error'].blank?

    render_success({
                     access_token: result[:access_token],
                     expires_in: result[:expires_in],
                     user: serialize_user(result[:user]),
                     session: serialize_session(Current.session)
                   })
  end

  # GET /sessions (list all user sessions)
  def index
    return render_unauthorized unless Current.user

    active_sessions = Current.user.active_sessions.map do |session|
      serialize_session_with_details(session, current: session == Current.session)
    end

    render_success({ sessions: active_sessions })
  end

  # GET /sessions/:token (show specific session)
  def show
    return render_unauthorized unless Current.user

    session = Current.user.sessions.find_by(uuid: params[:token])

    return render_not_found(Session) unless session

    render_success({
                     session: serialize_session_with_details(session, current: session == Current.session)
                   })
  end

  # DELETE /sessions (logout current)
  def destroy
    logout_current_session
    render_success({ message: 'Logged out successfully' })
  end

  # DELETE /sessions/:token (logout specific session)
  def destroy_session
    return render_unauthorized unless Current.user

    session = Current.user.sessions.find_by(uuid: params[:token])
    return render_not_found(Session) unless session

    # Don't allow destroying current session through this endpoint
    if session == Current.session
      return render_error('Use DELETE /sessions to logout current session', code: 'forbidden', status: :forbidden)
    end

    session.revoke!
    render_success({ message: 'Session revoked successfully' })
  end

  # DELETE /sessions/all (logout all other sessions)
  def all
    return render_unauthorized unless Current.user

    # Revoke all sessions except current one
    revoked_count = Current.user.sessions.active
                           .where.not(id: Current.session&.id)
                           .update_all(revoked_at: Time.current)

    # You could call Current.user.cleanup_sessions! Here

    render_success({
                     message: 'All other sessions revoked successfully', revoked_count:
                   })
  end

  private

  def session_params
    @session_params ||= params.require(:session).permit(:email, :password, :remember_me)
  end

  def authenticate_user(email, password)
    return nil if email.blank? || password.blank?

    user = User.find_by(email: email.downcase.strip)
    user&.authenticate(password)
  end

  def serialize_user(user)
    {
      uuid: user.uuid,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      full_name: user.full_name
    }
  end

  def serialize_session(session)
    {
      uuid: session.uuid,
      device: session.device_description,
      remember_me: session.remember_me?,
      expires_at: session.expires_at,
      current: session == Current.session
    }
  end

  def serialize_session_with_details(session, current: false)
    return unless session

    {
      uuid: session.uuid,
      device: session.device_description,
      location: session.location_info,
      last_activity: session.last_activity,
      created_at: session.created_at,
      expires_at: session.expires_at,
      remember_me: session.remember_me?,
      current:
    }
  end
end
