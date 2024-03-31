# frozen_string_literal: true

Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins ['simcoesignout.com', '127.0.0.1:5173', 'api.simcoesignout.com', 'staging.simcoesignout.com', 'stgapi.simcoesignout.com']

    resource '*',
             headers: :any,
             methods: %i[get post put patch delete options head],
             expose: %w[access-token expiry token-type Authorization],
             credentials: true
  end
end
