require 'rails_helper'

RSpec.describe RegistrationsController, type: :controller do
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

  describe 'POST #create' do
    let(:valid_registration_params) do
      {
        user: {
          email: 'newuser@example.com',
          password: 'password123',
          first_name: 'John',
          last_name: 'Doe',
          remember_me: true
        }
      }
    end

    let(:invalid_registration_params) do
      {
        user: {
          email: 'invalid-email',
          password: '123',
          first_name: '',
          last_name: ''
        }
      }
    end

    context 'with valid parameters' do
      it 'creates a new user' do
        expect do
          post :create, params: valid_registration_params
        end.to change(User, :count).by(1)
      end

      it 'creates a session for the new user' do
        expect do
          post :create, params: valid_registration_params
        end.to change(Session, :count).by(1)
      end

      it 'returns access token and user info' do
        post :create, params: valid_registration_params

        expect(response).to have_http_status(:created)

        expect(parsed_response['data']['access_token']).to be_present
        expect(parsed_response['data']['user']['email']).to eq('newuser@example.com')
        expect(parsed_response['data']['user']['full_name']).to eq('John Doe')
        expect(parsed_response['data']['session']).to be_present
        expect(parsed_response['data']['session']['remember_me']).to be true
      end

      it 'sets refresh token cookie' do
        post :create, params: valid_registration_params

        expect(response.cookies['refreshToken']).to be_present

        set_cookie_header = response.headers['Set-Cookie']
        expect(set_cookie_header).to include('httponly')
        expect(set_cookie_header).to include('samesite=lax')
      end
    end

    context 'with invalid parameters' do
      it 'does not create a user' do
        expect do
          post :create, params: invalid_registration_params
        end.not_to change(User, :count)
      end

      it 'returns validation errors' do
        post :create, params: invalid_registration_params

        expect(response).to have_http_status(:unprocessable_entity)

        expect(parsed_response['errors']).to match([
          {
            "code" => "validation_error",
            "field" => "first_name",
            "message" => "can't be blank"
          },
          {
            "code" => "validation_error",
            "field" => "last_name",
            "message" => "can't be blank"
          },
          {
            "code" => "validation_error",
            "field" => "password",
            "message" => "is too short (minimum is 6 characters)"
          }
        ])

        expect(parsed_response['data']).to be_nil
      end
    end

    context 'with duplicate email' do
      before do
        create(:user, email: 'newuser@example.com')
      end

      it 'returns validation error' do
        post :create, params: valid_registration_params

        expect(response).to have_http_status(:unprocessable_entity)

        expect(parsed_response['errors']).to match([
          {
            "code" => "validation_error",
            "field" => "email",
            "message" => "has already been taken"
          }
        ])
      end
    end
  end
end
