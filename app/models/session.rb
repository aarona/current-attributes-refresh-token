class Session < ApplicationRecord
  belongs_to :user

  after_initialize :ensure_uuid_token

  scope :active, -> { where(revoked_at: nil).where('expires_at > ?', Time.current) }

  normalizes :uuid, with: ->(uuid) { uuid.strip.downcase }

  validates :uuid, :expires_at, presence: true
  validates :uuid, uniqueness: { case_sensitive: false }

  def active? = revoked_at.nil? && expires_at > Time.current

  def device_description
    return 'Unknown Device' if user_agent.blank?

    case user_agent
    when /iPhone/
      'iPhone'
    when /iPad/
      'iPad'
    when /Android/
      'Android Device'
    when /Windows/
      'Windows Computer'
    when /Macintosh/
      'Mac Computer'
    when /Linux/
      'Linux Computer'
    else
      'Web Browser'
    end
  end

  # You could integrate with a GeoIP service here
  def location_info = ip_address || 'Unknown Location'
  def last_activity = last_accessed_at || created_at
  def revoke! = update!(revoked_at: Time.current)

  def extend_expiration!(remember_me: false)
    expiration_time = remember_me ? JwtConfig.remember_me_expiration : JwtConfig.refresh_token_expiration

    update!(expires_at: expiration_time.from_now, remember_me:)
  end

  private

  def ensure_uuid_token = self.uuid ||= SecureRandom.uuid
end
