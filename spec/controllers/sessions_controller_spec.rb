require 'rails_helper'

RSpec.describe SessionsController, type: :controller do
  let(:email) { 'user@example.com' }
  let(:password) { 'password123' }
  let!(:user) { create(:user, email:, password:) }

  before do
    JwtConfig.configure do |config|
      config.access_token_secret = 'test-access-secret'
      config.refresh_token_secret = 'test-refresh-secret'
      config.algorithm = 'HS256'
      config.access_token_expiration = 15.minutes
      config.refresh_token_expiration = 7.days
      config.remember_me_expiration = 30.days
    end
  end

  describe 'POST #create (login)' do
    let(:valid_credentials) { { session: { email:, password:, remember_me: false } } }
    let(:valid_credentials_with_remember_me) { { session: { email:, password:, remember_me: true } } }
    let(:invalid_credentials) { { session: { email:, password: 'wrong_password' } } }
    let(:missing_credentials) { { session: { email: '', password: '' } } }

    context 'with valid credentials' do
      it 'authenticates successfully' do
        post :create, params: valid_credentials

        expect(response).to have_http_status(:created)

        expect(parsed_response['data']['access_token']).to be_present
        expect(parsed_response['data']['expires_in']).to eq(JwtConfig.access_token_expiration.to_i)
        expect(parsed_response['data']['user']['email']).to eq(email)
        expect(parsed_response['data']['session']).to be_present
        expect(parsed_response['data']['session']['remember_me']).to be false
      end

      it 'creates a session record' do
        expect do
          post :create, params: valid_credentials
        end.to change(Session, :count).by(1)
      end

      it 'sets refresh token cookie' do
        post :create, params: valid_credentials

        expect(response.cookies['refreshToken']).to be_present

        set_cookie_header = response.headers['Set-Cookie']
        expect(set_cookie_header).to include('httponly')
        expect(set_cookie_header).to include('samesite=lax')
      end

      it 'sets Current.user and Current.session' do
        allow(Current).to receive(:user=)
        allow(Current).to receive(:session=)

        post :create, params: valid_credentials

        expect(Current).to have_received(:user=) do |set_user|
          expect(set_user).to eq user
        end

        expect(Current).to have_received(:session=) do |session|
          expect(session).to be_present
          expect(session.user).to eq user
        end
      end

      it 'includes user information in response' do
        post :create, params: valid_credentials

        user_data = parsed_response['data']['user']

        expect(user_data).to include(
          'uuid' => user.uuid,
          'email' => user.email,
          'first_name' => user.first_name,
          'last_name' => user.last_name,
          'full_name' => user.full_name
        )
      end

      it 'includes session information in response' do
        post :create, params: valid_credentials

        session_data = parsed_response['data']['session']

        expect(session_data).to include(
          'uuid', 'device', 'remember_me', 'expires_at', 'current'
        )
        expect(session_data['current']).to be true
        expect(session_data['remember_me']).to be false
      end
    end

    context 'with remember me option' do
      it 'creates session with extended expiration' do
        post :create, params: valid_credentials_with_remember_me

        expect(response).to have_http_status(:created)

        expect(parsed_response['data']['session']['remember_me']).to be true

        session = Session.last
        expect(session.remember_me?).to be true
        expect(session.expires_at).to be > 7.days.from_now
      end

      it 'sets cookie with extended expiration' do
        post :create, params: valid_credentials_with_remember_me

        cookie = response.cookies['refreshToken']

        expect(cookie).to be_present

        payload = Base64.decode64(cookie.split('.')[1])
        exp = JSON.parse(payload)['exp']

        expect(Time.at(exp)).to be > 7.days.from_now
      end
    end

    context 'with invalid credentials' do
      it 'returns unauthorized for wrong password' do
        post :create, params: invalid_credentials

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Invalid credentials')
      end

      it 'returns unauthorized for missing credentials' do
        post :create, params: missing_credentials

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Invalid credentials')
      end

      it 'does not create session for invalid login' do
        expect do
          post :create, params: invalid_credentials
        end.not_to change(Session, :count)
      end

      it 'does not set refresh token cookie for invalid login' do
        post :create, params: invalid_credentials

        expect(response.cookies['refreshToken']).to be_nil
      end
    end

    context 'with non-existent user' do
      let(:non_existent_user_credentials) do
        {
          session: {
            email: 'nonexistent@example.com',
            password:
          }
        }
      end

      it 'returns unauthorized' do
        post :create, params: non_existent_user_credentials

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Invalid credentials')
      end
    end
  end

  describe 'PATCH #update (refresh)' do
    let(:session) { create(:session, user:) }
    let(:valid_refresh_token) do
      create_refresh_token(user_id: user.uuid, session_token: session.uuid)
    end

    let(:expired_refresh_token) do
      create_refresh_token(user_id: user.uuid, session_token: session.uuid, expired: true)
    end

    context 'with valid refresh token' do
      include_context 'authenticated user'

      before do
        request.cookies['refreshToken'] = valid_refresh_token
      end

      it 'refreshes tokens successfully' do
        patch :update

        expect(response).to have_http_status(:ok)

        expect(parsed_response['data']['access_token']).to be_present
        expect(parsed_response['data']['expires_in']).to eq(JwtConfig.access_token_expiration.to_i)
        expect(parsed_response['data']['user']).to be_present
        expect(parsed_response['data']['session']).to be_present
      end

      it 'updates session activity' do
        expect(session).to receive(:update!).with(
          last_accessed_at: anything,
          user_agent: anything,
          ip_address: anything,
          expires_at: anything
        )

        patch :update
      end

      it 'sets new refresh token cookie' do
        patch :update

        expect(response.cookies['refreshToken']).to be_present
        expect(response.cookies['refreshToken']).not_to eq(valid_refresh_token)
      end

      it 'sets Current.user and Current.session' do
        current_user_calls = []
        current_session_calls = []

        allow(Current).to receive(:user).and_return(user)
        allow(Current).to receive(:user=) { |user| current_user_calls << user }

        allow(Current).to receive(:session).and_return(session)
        allow(Current).to receive(:session=) do |session|
          current_session_calls << session
        end

        patch :update

        # Ensure the last time Current.user= and .session=
        # were called, it was to set them.
        expect(current_user_calls.last).to_not be_nil
        expect(current_session_calls.last).to_not be_nil
      end
    end

    context 'with invalid refresh token' do
      include_context 'authenticated user'

      it 'returns unauthorized for missing refresh token' do
        patch :update

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end

      it 'returns unauthorized for expired refresh token' do
        request.cookies['refreshToken'] = expired_refresh_token

        patch :update

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end

      it 'returns unauthorized for malformed refresh token' do
        request.cookies['refreshToken'] = 'invalid_token'

        patch :update

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end
    end

    context 'with access token instead of refresh token' do
      let(:access_token) do
        # No 'type' field - this is an access token
        create_access_token(user_id: user.uuid, session_token: session.uuid)
      end

      it 'returns unauthorized' do
        request.cookies['refreshToken'] = access_token

        patch :update

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end
    end

    context 'with revoked session' do
      before do
        request.cookies['refreshToken'] = valid_refresh_token
        allow(Session).to receive(:find_by).with(uuid: session.uuid).and_return(session)
        allow(session).to receive(:active?).and_return(false)
      end

      it 'returns unauthorized' do
        patch :update

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end
    end
  end

  describe 'GET #index (list all sessions)' do
    let!(:session) { create(:session, user:, user_agent: 'Chrome Browser') }
    let!(:other_session) { create(:session, user:, user_agent: 'Safari Browser') }
    let!(:other_user_session) { create(:session, user: create(:user)) }

    context 'when authenticated' do
      include_context 'authenticated user'

      it 'returns all user sessions' do
        get :index

        expect(response).to have_http_status(:ok)

        sessions = parsed_response['data']['sessions']

        expect(sessions.length).to eq(2)
        expect(sessions.map { |s| s['uuid'] }).to contain_exactly(session.uuid, other_session.uuid)
      end

      it 'marks current session correctly' do
        allow(Current).to receive(:session).and_return(session)

        get :index

        sessions = parsed_response['data']['sessions']
        current_session = sessions.find { |s| s['current'] }

        expect(current_session['uuid']).to eq(session.uuid)
      end

      it 'includes session details' do
        get :index

        session_data = parsed_response['data']['sessions'].first

        expect(session_data).to include(
          'uuid', 'device', 'location', 'last_activity',
          'created_at', 'expires_at', 'remember_me', 'current'
        )
      end
    end

    context 'when not authenticated' do
      it 'returns unauthorized' do
        get :index

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end
    end
  end

  describe 'GET #show (show specific session)' do
    let(:session) { create(:session, user:) }
    let(:other_user_session) { create(:session, user: create(:user)) }

    context 'when authenticated' do
      include_context 'authenticated user'

      it 'returns session details for owned session' do
        get :show, params: { token: session.uuid }

        expect(response).to have_http_status(:ok)

        session_data = parsed_response['data']['session']

        expect(session_data['uuid']).to eq(session.uuid)
        expect(session_data).to include(
          'device', 'location', 'last_activity', 'created_at',
          'expires_at', 'remember_me', 'current'
        )
      end

      it 'marks current session correctly' do
        get :show, params: { token: session.uuid }

        expect(parsed_response['data']['session']['current']).to be true
      end

      it 'returns not found for non-existent session' do
        get :show, params: { token: 99_999 }

        expect(response).to have_http_status(:not_found)
        expect(parsed_response['errors'][0]['message']).to eq('Session not found')
      end

      it 'returns not found for other user session' do
        get :show, params: { token: other_user_session.uuid }

        expect(response).to have_http_status(:not_found)
        expect(parsed_response['errors'][0]['message']).to eq('Session not found')
      end
    end

    context 'when not authenticated' do
      it 'returns unauthorized' do
        get :show, params: { token: session.uuid }

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end
    end
  end

  describe 'DELETE #destroy (logout current session)' do
  context 'when authenticated' do
    include_context 'authenticated user'

    it 'logs out successfully' do
      expect(session).to receive(:update!).with(revoked_at: anything)

      delete :destroy

      expect(response).to have_http_status(:ok)
      expect(parsed_response['data']['message']).to eq('Logged out successfully')
    end

    it 'clears refresh token cookie' do
      allow(session).to receive(:update!).with(revoked_at: anything)

      delete :destroy

      expect(response.cookies['refreshToken']).to be_nil
    end

    it 'clears Current.user and Current.session' do
      current_user_calls = []
      current_session_calls = []

      allow(Current).to receive(:user).and_return(user)
      allow(Current).to receive(:user=) { |user| current_user_calls << user }

      allow(Current).to receive(:session).and_return(session)
      allow(Current).to receive(:session=) do |session|
        current_session_calls << session
      end

      allow(session).to receive(:update!).with(revoked_at: anything)

      delete :destroy

      # Ensure the last time Current.user= and .session=
      # were called, it was to clear them.
      expect(current_user_calls.last).to be_nil
      expect(current_session_calls.last).to be_nil
    end
  end
end

  describe 'DELETE #destroy_session (logout specific session)' do
    let(:current_session) { create(:session, user:) }
    let(:other_session) { create(:session, user:) }
    let(:other_user_session) { create(:session, user: create(:user)) }

    context 'when authenticated' do
      include_context 'authenticated user'

      it 'revokes the specified session' do
        delete :destroy_session, params: { token: other_session.uuid }

        expect(response).to have_http_status(:ok)
        expect(parsed_response['data']['message']).to eq('Session revoked successfully')

        expect(other_session.reload.revoked_at).to be_present
      end

      it 'prevents revoking current session' do
        allow(Current).to receive(:session).and_return(current_session)

        delete :destroy_session, params: { token: current_session.uuid }

        expect(response).to have_http_status(:forbidden)
        expect(parsed_response['errors'][0]['message']).to eq('Use DELETE /sessions to logout current session')
      end

      it 'returns not found for non-existent session' do
        delete :destroy_session, params: { token: 99_999 }

        expect(response).to have_http_status(:not_found)
        expect(parsed_response['errors'][0]['message']).to eq('Session not found')
      end

      it 'returns not found for other user session' do
        delete :destroy_session, params: { token: other_user_session.uuid }

        expect(response).to have_http_status(:not_found)
        expect(parsed_response['errors'][0]['message']).to eq('Session not found')
      end
    end

    context 'when not authenticated' do
      it 'returns unauthorized' do
        delete :destroy_session, params: { token: other_session.uuid }

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end
    end
  end

  describe 'DELETE #all (logout all other sessions)' do
    let(:current_session) { session }
    let!(:other_session1) { create(:session, user:) }
    let!(:other_session2) { create(:session, user:) }
    let!(:other_user_session) { create(:session, user: create(:user)) }

    context 'when authenticated' do
      include_context 'authenticated user'

      it 'revokes all other sessions' do
        delete :all

        expect(response).to have_http_status(:ok)

        expect(parsed_response['data']['message']).to eq('All other sessions revoked successfully')
        expect(parsed_response['data']['revoked_count']).to eq(2)
      end

      it 'keeps current session active' do
        delete :all

        expect(current_session.reload.active?).to be true
      end

      it 'revokes other user sessions for same user only' do
        delete :all

        expect(other_session1.reload.revoked_at).to be_present
        expect(other_session2.reload.revoked_at).to be_present
        expect(other_user_session.reload.active?).to be true # Different user's session untouched
      end

      context 'when user has no other sessions' do
        before do
          other_session1.destroy
          other_session2.destroy
        end

        it 'returns zero revoked count' do
          delete :all

          expect(response).to have_http_status(:ok)

          expect(parsed_response['data']['revoked_count']).to eq(0)
        end
      end
    end

    context 'when not authenticated' do
      it 'returns unauthorized' do
        delete :all

        expect(response).to have_http_status(:unauthorized)
        expect(parsed_response['errors'][0]['message']).to eq('Unauthorized')
      end
    end
  end
end
