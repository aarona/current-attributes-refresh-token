require 'rails_helper'

RSpec.describe User, type: :model do
  describe 'validations' do
    subject { build(:user) }
    it { should validate_presence_of(:email) }
    it { should validate_presence_of(:first_name) }
    it { should validate_presence_of(:last_name) }
    it { should validate_uniqueness_of(:email).case_insensitive }
    it { should validate_length_of(:password).is_at_least(6) }
  end

  describe 'associations' do
    it { should have_many(:sessions).dependent(:destroy) }
    it { should have_many(:active_sessions).class_name('Session') }
  end

  describe '#full_name' do
    let(:user) { build(:user, first_name: 'John', last_name: 'Doe') }

    it 'returns first and last name combined' do
      expect(user.full_name).to eq('John Doe')
    end
  end

  describe '#create_session!' do
    let(:user) { create(:user) }
    let(:ip_address) { '127.0.0.1' }
    let(:user_agent) { 'Test Browser' }

    before do
      allow(Current).to receive(:ip_address).and_return(ip_address)
      allow(Current).to receive(:user_agent).and_return(user_agent)
    end

    it 'creates a new session' do
      expect { user.create_session! }.to change(Session, :count).by(1)

      session = Session.last
      expect(session.ip_address).to eq ip_address
      expect(session.user_agent).to eq user_agent
    end

    it 'creates session with remember_me option' do
      session = user.create_session!(remember_me: true)
      expect(session.remember_me?).to be true
      expect(session.expires_at).to be > 7.days.from_now
    end
  end

  describe '#active_sessions' do
    let(:user) { create(:user) }

    before do
      create(:session, user:)
      create(:session, :expired, user:)
      create(:session, :revoked, user:)
    end

    it 'returns only active sessions' do
      expect(user.active_sessions.count).to eq(1)
    end
  end
end
