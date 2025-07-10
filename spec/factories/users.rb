FactoryBot.define do
  factory :user do
    uuid { SecureRandom.uuid }
    sequence(:email) { |n| "user#{n}@example.com" }
    password { 'password123' }
    first_name { 'John' }
    last_name { 'Doe' }

    trait :with_sessions do
      after(:create) do |user|
        create_list(:session, 2, user:)
      end
    end
  end
end
