Rails.application.config.middleware.insert_before 0, Rack::Cors do
  # Port 5173 is the default port for a Vite + React application.
  # You can also pass a comma delimited list of application URLs
  # if you want to have multiple applications in a system leverage
  # this application as an authentication service.
  allowed_origins = ENV.fetch('ALLOWED_ORIGINS', 'http://localhost:5173').to_s.split(',')

  allow do
    origins(*allowed_origins)

    resource '*',
             headers: :any,
             methods: %i[get post put patch delete options head],
             credentials: true
  end
end
