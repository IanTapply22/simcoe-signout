# frozen_string_literal: true

Rails.application.config.middleware.use OmniAuth::Builder do
  if Rails.env.production?
    if ENV['RESTRICT_LOGIN_BY_ORGANIZATION'] == 'false' # Should be kept as false from now on; Deprecating soon
      provider :google_oauth2, ENV.fetch('GOOGLE_CLIENT_ID', nil), ENV.fetch('GOOGLE_CLIENT_SECRET', nil),
               skip_jwt: true, scope: 'email, profile', redirect_uri: 'https://api.simcoesignout.com/users/auth/google_oauth2/callback'
    else
      provider :google_oauth2, ENV.fetch('GOOGLE_CLIENT_ID', nil), ENV.fetch('GOOGLE_CLIENT_SECRET', nil),
               skip_jwt: true, scope: 'email, profile', hd: 'dsbn.org', redirect_uri: 'https://api.simcoesignout.com/users/auth/google_oauth2/callback'
    end
  end

  if Rails.env.development?
    provider :google_oauth2, ENV.fetch('GOOGLE_CLIENT_ID', nil), ENV.fetch('GOOGLE_CLIENT_SECRET', nil),
             skip_jwt: true, scope: 'email, profile', redirect_uri: 'http://127.0.0.1:3000/users/auth/google_oauth2/callback'
  end

  if Rails.env.staging?
    provider :google_oauth2, ENV.fetch('GOOGLE_CLIENT_ID', nil), ENV.fetch('GOOGLE_CLIENT_SECRET', nil),
              skip_jwt: true, scope: 'email, profile', redirect_uri: 'https://stg.api.simcoesignout.com/users/auth/google_oauth2/callback'
  end
end
OmniAuth.config.allowed_request_methods = %i[get]
