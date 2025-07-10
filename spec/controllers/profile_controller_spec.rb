require 'rails_helper'

RSpec.describe ProfileController, type: :controller do
  let(:user) { create(:user) }
  let(:session) { create(:session, user:) }

  before do
    JwtConfig.configure do |config|
      config.access_token_secret = 'test-access-secret'
      config.refresh_token_secret = 'test-refresh-secret'
      config.algorithm = 'HS256'
      config.access_token_expiration = 15.minutes
      config.refresh_token_expiration = 7.days
    end
  end

  describe 'GET #show' do
    context 'when authenticated' do
      include_context 'authenticated user'

      it 'returns user profile information' do
        get :show

        expect(response).to have_http_status(:ok)

        expect(parsed_response['data']['user']['uuid']).to eq(user.uuid)
        expect(parsed_response['data']['user']['email']).to eq(user.email)
        expect(parsed_response['data']['user']['first_name']).to eq(user.first_name)
        expect(parsed_response['data']['user']['last_name']).to eq(user.last_name)
        expect(parsed_response['data']['user']['full_name']).to eq(user.full_name)
        expect(parsed_response['data']['user']['created_at']).to be_present
        expect(parsed_response['data']['session']['uuid']).to eq(session.uuid)
        expect(parsed_response['data']['session']['remember_me']).to eq(session.remember_me?)
      end

      it 'includes session information' do
        get :show

        expect(response).to have_http_status(:ok)

        expect(parsed_response['data']['session']).to include(
          'uuid', 'device', 'last_activity', 'expires_at', 'remember_me', 'current'
        )
        expect(parsed_response['data']['session']['current']).to be true
      end
    end

    context 'when not authenticated' do
      it 'returns unauthorized' do
        get :show

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end
    end
  end
end
