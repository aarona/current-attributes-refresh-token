# JwtRefreshAccessAuthentication Usage Guide - Rails 8+ Edition

This authentication system is built specifically to support Rails 8 `ActiveSupport::CurrentAttributes` with a Rails **API only** application and follows the [Omakase](https://en.wikipedia.org/wiki/Omakase) philosophy championed by [David Heinemeier Hansson (DHH)](https://dhh.dk/), the creator of [Ruby on Rails](https://rubyonrails.org/). True to this philosophy, this project is intentionally provided as a curated set of code snippets rather than a packaged gem, giving you the flexibility to understand, modify, and adapt the authentication logic to your specific needs.

## Key Features

### Modern Implementation
- **Current Context**: Uses Rails 8 `Current` attributes for user and session tracking

### Fully Featured Session Management
- **Configurable Expiration**: Environment-specific token lifetimes
- **Device Tracking**: User agent and IP address tracking for security
- **Sliding Expiration**: Refresh tokens update session expiration
- **Multi-Device Support**: Users can have multiple active sessions
- **Automatic Cleanup**: Expired sessions can be automatically cleaned up
- **Max Sessions**: Configurable limit on concurrent sessions per user
- **Separate Secrets**: Access and refresh tokens use different secrets
- **Revocation Support**: Sessions can be individually or bulk revoked
- **Secure Refresh Tokens in Cookies**: httpOnly, secure, and sameSite attributes in production
- **Device Information**: Track user agent and IP for security monitoring
- **Token Rotation**: Refresh tokens are regenerated on each use

## Some Caveats

Rails 8 authentication doesn't have registration out of the box by design because it is a very bespoke operation and should be left up to the developer for implementation. Since I needed a registration process, I included mine (first and last name and email) but this project is intended to be modified to your needs. The ability to update your password for example has not been implemented yet. I may come back to this in the future but don't need it for my purposes right now. Rate limiting using a library like [Rack::Attack](https://github.com/rack/rack-attack) would also be advised.

## Setup Instructions

### 1. Satisfy the following prerequisites
These instructions assume you've already created a Rails 8.0+ application using the `--api` option (or your `ApplicationController` is derived from `ActionController::API`). You will also need the following gems listed in your `Gemfile`:

```ruby
gem 'bcrypt'
gem 'rack-cors'
gem 'jwt'

group :development, :test do
  gem 'factory_bot_rails'

  # If you're just now adding rspec-rails to
  # your project be sure to run:
  # rails g rspec:install
  # after you bundle install these new Gems.
  gem 'rspec-rails'
end

group :test do
  gem 'shoulda-matchers'
  gem 'timecop'
end
```

### 2. Copy / Merge the files in this project into your Rails application

The idea here is that you want to copy the files in this project to the relative locations in your application. If you've already ran `rails generate authentication` to generate the default Rails 8 authentication files, you'll need to merge some of this code like the models and the database migrations into what you currently have. You might need to create extra database migrations to add the fields in if your `users` and `sessions` tables already exist.

### 3. Run the migrations

You will need to rename the migration files by changing the `xxx_...` to a legitimate timestamp like you'd normally have with a database migration file name.

```bash
rails db:migrate
```

### 4. Set up credentials

You can generate good keys by running `rails secret`. Security best practices strongly suggest that you use different keys for each token generation.

```bash
# Add JWT secrets to your credentials
rails credentials:edit

# Add these lines to your credentials file:
jwt_access_secret: your-super-secret-access-key-here
jwt_refresh_secret: your-different-super-secret-refresh-key-here
```

### 5. Run RSpec tests

Assuming the copying of these files went well and you didn't need to merge anything complex that could cause your tests to fail, all of the tests that came from this project should pass.

```bash
rspec .
```

## API Endpoints

You have everything you need to get started. Build upon these for other useful features, like those in Devise for example.

| HTTP Verb | Path | Description |
|-----------|------|-------------|
| POST | `/registrations` | Sign up (create account + auto-login) |
| POST | `/sessions` | Sign in (login) |
| GET | `/sessions` | List all user sessions |
| GET | `/sessions/:token` | Show specific session |
| PUT/PATCH | `/sessions` | Refresh current session |
| DELETE | `/sessions` | Sign out current session |
| DELETE | `/sessions/:token` | Sign out specific session |
| DELETE | `/sessions/all` | Sign out all other sessions |
| GET | `/profile` | Get current user profile |

## Usage Examples (with cURL)

### Registration (Sign Up)

```bash
# Save the returned refresh token cookie in
# cookies.txt to request new access tokens later on.
# 
# remember_me is optional and defaults to false. Sending
# it as true will use the remember_me token expiration
# which is typically much longer than without it.
curl -X POST http://localhost:3000/registrations \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0 (iPhone)" \
  -d '{
    "user": {
      "email": "user@example.com",
      "password": "password123",
      "first_name": "John",
      "last_name": "Doe",
      "remember_me": false
    }
  }' \
  -c cookies.txt
```

Response:
```json
// Successful respose example:
{
  "data": {
    "access_token":"eyJhbGciOiJIUzI1NiJ9...",
    "expires_in": 3600,
    "user": {
      "uuid": "5cc9e743-7602-4071-87a7-af4291beb9e8",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "full_name": "John Doe"
    },
    "session": {
      "uuid": "c1870458-2868-41fd-8694-2916b3add157",
      "device": "iPhone",
      "remember_me": false,
      "expires_at": "2025-08-04T08:50:24.872Z",
      "current": true
    }
  },
  "meta":{},
  "errors":[]
}

// Missing fields example:
{
  "data": null,
  "meta": {},
  "errors": [
    {
      "field": "email",
      "message": "has already been taken",
      "code": "validation_error"
    },
    {
      "field":"last_name",
      "message":"can't be blank",
      "code":"validation_error"
    },
    {
      "field": "password",
      "message": "is too short (minimum is 6 characters)",
      "code": "validation_error"
    }
  ]
}
```

### Login (Sign In)

```bash
# Save the returned refresh token as a cookie
# to request new access tokens later on.
curl -X POST http://localhost:3000/sessions \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0 (iPhone)" \
  -d '{
    "session": {
      "email": "user@example.com",
      "password": "password123",
      "remember_me": false
    }
  }' \
  -c cookies.txt
```

Response:
```json
// Successful Sign-in
{
  "data": {
    "access_token":"eyJhbGciOiJIUzI1NiJ9...",
    "expires_in": 3600,
    "user": {
      "uuid": "5cc9e743-7602-4071-87a7-af4291beb9e8",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "full_name": "John Doe"
    },
    "session": {
      "uuid": "3db658ad-3529-41fe-a4fb-b1acb09c547a",
      "device": "iPhone",
      "remember_me": false,
      "expires_at": "2025-08-04T08:56:15.492Z",
      "current": true
    }
  },
  "meta": {},
  "errors": []
}

// Entered wrong password
{
  "data": null,
  "meta": {},
  "errors": [
    {
      "message":"Invalid credentials",
      "code":"invalid_credentials"
    }
  ]
}
```

### Login with Remember Me

```bash
curl -X POST http://localhost:3000/sessions \
  -H "Content-Type: application/json" \
  -H "User-Agent: MyApp/1.0 (iPhone)" \
  -d '{
    "session": {
      "email": "user@example.com",
      "password": "password123",
      "remember_me": true
    }
  }' \
  -c cookies.txt
```

Response:
```json
{
  "data": {
    "access_token":"eyJhbGciOiJIUzI1NiJ9...",
    "expires_in": 3600,
    "user": {
      "uuid": "5cc9e743-7602-4071-87a7-af4291beb9e8",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "full_name": "John Doe"
    },
    "session": {
      "uuid":"88b8a4af-6cf4-4e4c-a2fd-6cd19367dd37",
      "device": "iPhone",
      "remember_me": true,
      "expires_at": "2025-10-03T15:37:15.511Z",
      "current": true
    }
  },
  "meta":{},
  "errors":[]
}
```

### Using Access Token with Session Context

```bash
curl -X GET http://localhost:3000/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..." \
  -H "User-Agent: MyApp/1.0 (iPhone)"
```

Response:
```json
{
  "data": {
    "user": {
      "uuid": "5cc9e743-7602-4071-87a7-af4291beb9e8",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "full_name": "John Doe",
      "created_at": "2025-07-05T08:50:24.867Z"
    },
    "session": {
      "uuid": "88b8a4af-6cf4-4e4c-a2fd-6cd19367dd37",
      "device": "iPhone",
      "last_activity": "2025-07-05T15:37:15.513Z",
      "expires_at": "2025-10-03T15:37:15.511Z",
      "remember_me": true,
      "current": true
    }
  },
  "meta":{},
  "errors":[]
}
```

### Refresh Session

```bash
curl -X PATCH http://localhost:3000/sessions \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -c cookies.txt
```

### Session Management

```bash
# List all sessions
curl -X GET http://localhost:3000/sessions \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."

# Show specific session
curl -X GET http://localhost:3000/sessions/409a7ec9-98... \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."

# Logout all other sessions
curl -X DELETE http://localhost:3000/sessions/all \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."

# Logout current session
curl -X DELETE http://localhost:3000/sessions \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."
```

## Controller Examples

### Basic Protected Controller

```ruby
class PostsController < ApplicationController
  include JwtRefreshAccessAuthentication

  # Requires authentication
  before_action :authenticate_request

  def index
    render json: { 
      posts: Post.all,
      current_user: Current.user.full_name
    }
  end

  def create
    post = Current.user.posts.create(post_params)
    render json: { 
      post: post,
      created_by: Current.user.full_name
    }
  end

  private

  def post_params
    params.require(:post).permit(:title, :content)
  end
end
```

### Mixed Public/Private Controller

```ruby
class ArticlesController < ApplicationController
  include JwtRefreshAccessAuthentication

  skip_before_action :authenticate_request, only: [:index, :show]

  # Public endpoint
  def index
    render json: { 
      articles: Article.published,
      authenticated: Current.logged_in?
    }
  end

  # Public endpoint
  def show
    render json: { article: Article.find(params[:id]) }
  end

  # Private endpoint - requires authentication
  def create
    article = Current.user.articles.create(article_params)
    render json: { article: article }
  end

  private

  def article_params
    params.require(:article).permit(:title, :content)
  end
end
```

## Testing Your Application

### Using Factories and Shared Examples

```ruby
# spec/controllers/posts_controller_spec.rb
require 'rails_helper'

RSpec.describe PostsController, type: :controller do
  let(:user) { create(:user) }
  
  describe 'GET #index' do    
    context 'when authenticated' do
      include_context 'authenticated user'

      it 'returns posts with user context' do
        get :index
        
        expect(response).to have_http_status(:ok)
        expect(parsed_response['current_user']).to eq(user.full_name)
      end
    end
  end
end
```

## Background Jobs

Consider adding background jobs for session management:

```ruby
# app/jobs/session_cleanup_job.rb
class SessionCleanupJob < ApplicationJob
  def perform
    # Clean up expired sessions
    Session.where('expires_at < ?', Time.current).delete_all
    
    # Clean up revoked sessions older than 30 days
    Session.where('revoked_at < ?', 30.days.ago).delete_all
  end
end

# config/schedule.yml (a Solid Queue example)
session_cleanup:
  class: SessionCleanupJob
  # Daily at midnight
  cron: "0 0 * * *"
  queue: maintenance
```