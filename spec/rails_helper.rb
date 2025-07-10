RSpec.configure do |config|
  # Place this inside your Rspec config block
  config.include FactoryBot::Syntax::Methods
end

# Place this under the RSpec.configure block
Dir['./spec/support/**/*.rb'].sort.each { |f| require f }

Shoulda::Matchers.configure do |config|
  config.integrate do |with|
    with.test_framework :rspec
    with.library :rails
  end
end
