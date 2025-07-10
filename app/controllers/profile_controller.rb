class ProfileController < ApplicationController
  # GET /profile
  def show
    render_success({
                     user: serialize_user(Current.user),
                     session: serialize_session(Current.session)
                   })
  end

  private

  def serialize_user(user)
    {
      uuid: user.uuid,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      full_name: user.full_name,
      created_at: user.created_at
    }
  end

  def serialize_session(session)
    return nil unless session

    {
      uuid: session.uuid,
      device: session.device_description,
      last_activity: session.last_activity,
      expires_at: session.expires_at,
      remember_me: session.remember_me?,
      current: true
    }
  end
end
