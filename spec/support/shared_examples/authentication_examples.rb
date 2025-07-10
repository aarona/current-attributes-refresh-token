RSpec.shared_context 'authenticated user' do
  let(:user) { create(:user) }
  let(:session) { create(:session, user:) }
  let(:valid_token) { create_access_token(user_id: user.uuid, session_token: session.uuid) }

  before do
    request.headers['Authorization'] = "Bearer #{valid_token}"
    allow(Session).to receive(:find_by).and_return(session)
  end
end
