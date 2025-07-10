class Current < ActiveSupport::CurrentAttributes
  attribute :user, :session, :user_agent, :ip_address, :request_id

  def user=(user)
    previous_user = attributes[:user]
    super

    # Clear session if user actually changed
    return unless user != previous_user && session.present?

    attributes[:session] = nil
  end

  def session=(session)
    super
    attributes[:user] = session&.user
  end

  def logged_in? = user.present?
  def session_active? = session&.active?
  def device_info = { user_agent:, ip_address:, request_id: }
end
