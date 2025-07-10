# Example User model integration
class User < ApplicationRecord
  has_secure_password

  has_many :sessions, dependent: :destroy
  has_many :active_sessions, -> { active.order(last_accessed_at: :desc) }, class_name: 'Session'

  after_initialize :ensure_uuid

  normalizes :uuid, with: ->(uuid) { uuid.strip.downcase }
  normalizes :email, with: ->(email) { email.strip.downcase }

  validates :uuid, :email, uniqueness: { case_sensitive: false }
  validates :uuid, :email, :first_name, :last_name, presence: true
  validates :password, length: { minimum: 6 }

  def full_name = [first_name, last_name].compact.join(' ')

  def cleanup_sessions!
    sessions.where('expires_at < ? OR revoked_at IS NOT NULL', Time.current).destroy_all
  end

  # Revoke all sessions (useful for password changes, etc.)
  def revoke_all_sessions! = sessions.update_all(revoked_at: Time.current)

  def create_session!(remember_me: false)
    # If we're creating a new session, might
    # as well clean up old sessions first.
    # You could also run session cleanup as
    # a nightly job.
    cleanup_sessions!

    expiration_time = remember_me ? JwtConfig.remember_me_expiration : JwtConfig.refresh_token_expiration

    sessions.create!(
      uuid: SecureRandom.uuid,
      user_agent: Current.user_agent,
      ip_address: Current.ip_address,
      remember_me:,
      expires_at: expiration_time.from_now,
      last_accessed_at: Time.current
    )
  end

  private

  def ensure_uuid = self.uuid ||= SecureRandom.uuid
end
