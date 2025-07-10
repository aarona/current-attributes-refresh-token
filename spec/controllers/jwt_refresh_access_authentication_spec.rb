require 'rails_helper'

RSpec.describe JwtRefreshAccessAuthentication, type: :controller do
  # Create a test controller that includes the concern
  controller(ApplicationController) do
    include JwtRefreshAccessAuthentication

    def index
      render json: { message: 'success', user_id: Current.user&.uuid }
    end

    def show
      render json: { user: Current.user, session: Current.session&.uuid }
    end
  end

  let(:user) { create(:user) }
  let(:valid_user_id) { user.uuid }
  let(:invalid_user_id) { SecureRandom.uuid }
  let(:test_session_token) { SecureRandom.uuid }

  before do
    # Configure JWT settings for tests
    JwtConfig.configure do |config|
      config.access_token_secret = 'test-access-secret'
      config.refresh_token_secret = 'test-refresh-secret'
      config.algorithm = 'HS256'
      config.access_token_expiration = 15.minutes
      config.refresh_token_expiration = 7.days
    end

    routes.draw do
      get 'index' => 'anonymous#index'
      get 'show' => 'anonymous#show'
    end
  end

  describe '#authenticate_request' do
    let(:mock_session) do
      create(:session, uuid: test_session_token, user:)
    end

    context 'with valid JWT token' do
      let(:valid_token) do
        create_access_token(user_id: valid_user_id, session_token: test_session_token)
      end

      before do
        allow(Current).to receive(:user=)
        allow(Session).to receive(:find_by).with(
          uuid: test_session_token,
          user:
        ).and_return(mock_session)
      end

      it 'authenticates successfully and sets Current.user' do
        request.headers['Authorization'] = "Bearer #{valid_token}"

        get :index

        expect(response).to have_http_status(:ok)
        expect(parsed_response['user_id']).to eq(valid_user_id)
        expect(Current).to have_received(:user=) do |user|
          expect(user.uuid).to eq(valid_user_id)
        end
      end

      it 'sets Current.session when session_token is present' do
        allow(Current).to receive(:session=)

        request.headers['Authorization'] = "Bearer #{valid_token}"
        get :show

        expect(response).to have_http_status(:ok)
        expect(Current).to have_received(:session=) do |session|
          expect(session.id).to eq(mock_session.id)
        end
      end
    end

    context 'with token without session_token' do
      let(:token_without_session) do
        create_access_token(user_id: valid_user_id)
      end

      before do
        allow(Current).to receive(:user=)
        allow(Current).to receive(:session=)
      end

      it 'authenticates but does not set Current.session' do
        request.headers['Authorization'] = "Bearer #{token_without_session}"
        get :index

        expect(response).to have_http_status(:ok)
        expect(Current).to have_received(:user=) do |user|
          expect(user.uuid).to eq(valid_user_id)
        end
        expect(Current).to_not have_received(:session=)
      end
    end

    context 'with invalid JWT token' do
      before { allow(Current).to receive(:user=) }

      it 'returns unauthorized for malformed token' do
        request.headers['Authorization'] = 'Bearer invalid_token'

        get :index

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
        expect(Current).not_to have_received(:user=)
      end

      it 'returns unauthorized for expired token' do
        expired_payload = {
          user_id: valid_user_id,
          exp: 1.hour.ago.to_i,
          iat: 2.hours.ago.to_i
        }
        expired_token = JWT.encode(expired_payload, JwtConfig.access_token_secret, JwtConfig.algorithm)
        request.headers['Authorization'] = "Bearer #{expired_token}"

        get :index

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
        expect(Current).not_to have_received(:user=)
      end

      it 'returns unauthorized for token with invalid user' do
        invalid_user_payload = {
          user_id: invalid_user_id,
          exp: 1.hour.from_now.to_i,
          iat: Time.current.to_i
        }
        invalid_user_token = JWT.encode(invalid_user_payload, JwtConfig.access_token_secret, JwtConfig.algorithm)
        request.headers['Authorization'] = "Bearer #{invalid_user_token}"

        get :index

        expect(response).to have_http_status(:unauthorized)
        expect(Current).not_to have_received(:user=)
      end
    end

    context 'without Authorization header' do
      before { allow(Current).to receive(:user=) }

      it 'returns unauthorized' do
        get :index

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
        expect(Current).not_to have_received(:user=)
      end
    end
  end
end
