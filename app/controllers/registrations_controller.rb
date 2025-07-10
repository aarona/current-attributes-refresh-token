class RegistrationsController < ApplicationController
  skip_before_action :authenticate_request

  # POST /registrations
  def create
    user = User.new(registration_params.except(:remember_me))

    if user.save
      # TODO: Add asynchronous notification (Mailer Job?) to user about
      # their new account. Also everything in this block could be extracted
      # into a service class probably after its sucessfully integrated into
      # your app.

      remember_me = [true, 'true'].include?(registration_params[:remember_me])

      # Create a new session for this registration (auto-login)
      session = user.create_session!(remember_me:)

      # Set current context
      Current.user = user
      Current.session = session

      # Generate tokens
      access_token = generate_access_token(user:, session:)
      refresh_token = generate_refresh_token(user:, session:)

      # Set refresh token cookie with appropriate expiration
      set_refresh_token_cookie(refresh_token, remember_me:)

      render_success(
        {
          access_token:,
          expires_in: JwtConfig.access_token_expiration.to_i,
          user: serialize_user(user),
          session: serialize_session(session)
        }, status: :created
      )
    else
      render_validation_errors(user)
    end
  end

  private

  def registration_params
    @registration_params ||= params.require(:user).permit(:email, :password, :first_name, :last_name, :remember_me)
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
      current: true
    }
  end
end
