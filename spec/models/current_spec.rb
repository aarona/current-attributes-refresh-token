require 'rails_helper'

RSpec.describe Current do
  let(:user) { create(:user, email: 'test@example.com') }
  let(:session) { double('Session', user:) }

  describe 'user assignment' do
    it 'clears session when user changes' do
      Current.user = user
      Current.session = session
      Current.user = create(:user, email: 'other@example.com')

      expect(Current.session).to be_nil
    end

    it 'does not clear session when same user is assigned' do
      Current.user = user
      Current.session = session

      Current.user = user

      expect(Current.session).to eq(session)
    end
  end

  describe 'session assignment' do
    it 'sets user from session' do
      Current.session = session

      expect(Current.user).to eq(user)
    end

    it 'allows nil session' do
      Current.session = nil

      expect(Current.user).to be_nil
    end
  end

  describe 'helper methods' do
    it 'returns true for logged_in? when user present' do
      Current.user = user
      expect(Current.logged_in?).to be true
    end

    it 'returns false for logged_in? when user absent' do
      Current.user = nil
      expect(Current.logged_in?).to be false
    end

    it 'returns device_info hash' do
      Current.user_agent = 'Test Browser'
      Current.ip_address = '127.0.0.1'
      Current.request_id = 'test-request'

      info = Current.device_info
      expect(info[:user_agent]).to eq('Test Browser')
      expect(info[:ip_address]).to eq('127.0.0.1')
      expect(info[:request_id]).to eq('test-request')
    end
  end
end
