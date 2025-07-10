require 'rails_helper'

RSpec.describe Session, type: :model do
  describe 'validations' do
    it { should belong_to(:user) }
    it { should validate_presence_of(:uuid) }
    it { should validate_presence_of(:expires_at) }
  end

  describe 'associations' do
    it { should belong_to(:user) }
  end

  describe 'callbacks' do
    describe 'after_intialize :ensure_uuid_token' do
      it 'generates a token upon initialize' do
        session = Session.new

        expect(session.uuid).to be_present
      end

      it 'does not override existing token' do
        user = create(:user)
        existing_token = SecureRandom.uuid
        session = Session.new(user:, uuid: existing_token, expires_at: 1.day.from_now)

        session.save!
        expect(session.uuid).to eq(existing_token)
      end
    end
  end

  describe 'scopes' do
    let(:user) { create(:user) }

    before do
      create(:session, user:, expires_at: 1.day.from_now, revoked_at: nil)
      create(:session, user:, expires_at: 1.day.ago, revoked_at: nil) # expired
      create(:session, user:, expires_at: 1.day.from_now, revoked_at: 1.hour.ago) # revoked
    end

    describe '.active' do
      it 'returns only non-revoked, non-expired sessions' do
        expect(Session.active.count).to eq(1)
      end

      it 'excludes expired sessions' do
        expired_sessions = Session.where('expires_at < ?', Time.current)
        expect(Session.active).not_to include(*expired_sessions)
      end

      it 'excludes revoked sessions' do
        revoked_sessions = Session.where.not(revoked_at: nil)
        expect(Session.active).not_to include(*revoked_sessions)
      end
    end
  end

  describe '#active?' do
    let(:user) { create(:user) }

    it 'returns true for active session' do
      session = create(:session, user:, expires_at: 1.day.from_now, revoked_at: nil)
      expect(session.active?).to be true
    end

    it 'returns false for expired session' do
      session = create(:session, user:, expires_at: 1.day.ago, revoked_at: nil)
      expect(session.active?).to be false
    end

    it 'returns false for revoked session' do
      session = create(:session, user:, expires_at: 1.day.from_now, revoked_at: 1.hour.ago)
      expect(session.active?).to be false
    end

    it 'returns false for both expired and revoked session' do
      session = create(:session, user:, expires_at: 1.day.ago, revoked_at: 1.hour.ago)
      expect(session.active?).to be false
    end
  end

  describe '#revoke!' do
    let(:session) { create(:session) }

    it 'sets revoked_at timestamp' do
      expect do
        session.revoke!
      end.to change { session.reload.revoked_at }.from(nil).to(be_within(1.second).of(Time.current))
    end

    it 'makes session inactive' do
      session.revoke!
      expect(session.reload.active?).to be false
    end

    it 'persists the revocation' do
      session.revoke!
      reloaded_session = Session.find(session.id)
      expect(reloaded_session.revoked_at).to be_present
    end
  end

  describe '#extend_expiration!' do
    let(:session) { create(:session, remember_me: false) }

    before do
      JwtConfig.configure do |config|
        config.refresh_token_expiration = 7.days
        config.remember_me_expiration = 30.days
      end
    end

    it 'extends expiration for regular session' do
      original_expiration = session.expires_at

      travel_to 1.hour.from_now do
        session.extend_expiration!(remember_me: false)
        expect(session.reload.expires_at).to be > original_expiration
        expect(session.expires_at).to be_within(1.minute).of(7.days.from_now)
      end
    end

    it 'extends expiration for remember me session' do
      travel_to 1.hour.from_now do
        session.extend_expiration!(remember_me: true)
        expect(session.reload.expires_at).to be_within(1.minute).of(30.days.from_now)
        expect(session.remember_me?).to be true
      end
    end

    it 'updates remember_me flag' do
      expect do
        session.extend_expiration!(remember_me: true)
      end.to change { session.reload.remember_me? }.from(false).to(true)
    end
  end

  describe '#device_description' do
    let(:user) { create(:user) }

    it 'returns "Unknown Device" when user_agent is blank' do
      session = create(:session, user:, user_agent: nil)
      expect(session.device_description).to eq('Unknown Device')
    end

    it 'detects iPhone from user agent' do
      user_agent = 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15'
      session = create(:session, user:, user_agent:)
      expect(session.device_description).to eq('iPhone')
    end

    it 'detects iPad from user agent' do
      user_agent = 'Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15'
      session = create(:session, user:, user_agent:)
      expect(session.device_description).to eq('iPad')
    end

    it 'detects Android from user agent' do
      user_agent = 'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36'
      session = create(:session, user:, user_agent:)
      expect(session.device_description).to eq('Android Device')
    end

    it 'detects Windows from user agent' do
      user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      session = create(:session, user:, user_agent:)
      expect(session.device_description).to eq('Windows Computer')
    end

    it 'detects Mac from user agent' do
      user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
      session = create(:session, user:, user_agent:)
      expect(session.device_description).to eq('Mac Computer')
    end

    it 'detects Linux from user agent' do
      user_agent = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
      session = create(:session, user:, user_agent:)
      expect(session.device_description).to eq('Linux Computer')
    end

    it 'returns generic "Web Browser" for unknown user agents' do
      user_agent = 'SomeCustomBrowser/1.0'
      session = create(:session, user:, user_agent:)
      expect(session.device_description).to eq('Web Browser')
    end
  end

  describe '#location_info' do
    let(:user) { create(:user) }

    it 'returns IP address when present' do
      session = create(:session, user:, ip_address: '192.168.1.100')
      expect(session.location_info).to eq('192.168.1.100')
    end

    it 'returns "Unknown Location" when IP address is blank' do
      session = create(:session, user:, ip_address: nil)
      expect(session.location_info).to eq('Unknown Location')
    end
  end

  describe '#last_activity' do
    let(:user) { create(:user) }

    it 'returns last_accessed_at when present' do
      last_accessed_at = 2.hours.ago
      session = create(:session, user:, last_accessed_at:)
      expect(session.last_activity).to be_within(1.second).of(last_accessed_at)
    end

    it 'returns created_at when last_accessed_at is nil' do
      session = create(:session, user:, last_accessed_at: nil)
      expect(session.last_activity).to eq(session.created_at)
    end
  end
end
