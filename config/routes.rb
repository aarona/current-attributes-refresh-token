Rails.application.routes.draw do
  # Sign up (create account + auto-login)
  post 'registrations', to: 'registrations#create'

  # Sign in
  post 'sessions', to: 'sessions#create'

  # List all sessions
  get 'sessions', to: 'sessions#index'

  # Show specific session
  get 'sessions/:token', to: 'sessions#show'

  # Refresh current session
  put 'sessions', to: 'sessions#update'
  patch 'sessions', to: 'sessions#update'

  # Sign out all other sessions
  delete 'sessions/all', to: 'sessions#all'

  # Sign out current session
  delete 'sessions', to: 'sessions#destroy'

  # Sign out specific session
  delete 'sessions/:token', to: 'sessions#destroy_session'

  # User profile
  get 'profile' => 'profile#show'

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get 'up' => 'rails/health#show', as: :rails_health_check

  # Defines the root path route ("/")
  # root "posts#index"
end
