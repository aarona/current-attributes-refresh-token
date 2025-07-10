FactoryBot.define do
  factory :session do
    association :user
    uuid { SecureRandom.uuid }
    remember_me { false }
    user_agent { 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' }
    ip_address { '192.168.1.100' }
    last_accessed_at { Time.current }
    expires_at { 7.days.from_now }

    trait :remember_me do
      remember_me { true }
      expires_at { 30.days.from_now }
    end

    trait :expired do
      expires_at { 1.day.ago }
    end

    trait :revoked do
      revoked_at { 1.hour.ago }
    end

    trait :mobile do
      user_agent { 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)' }
    end
  end
end
