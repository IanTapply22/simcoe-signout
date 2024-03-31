# frozen_string_literal: true

class JsonWebToken
  class << self
    def encode(payload, exp = 30.minutes.from_now)
      payload[:exp] = exp.to_i
      JWT.encode(payload, ENV.fetch('JWT_ENCRYPTION_KEY', nil))
    end

    def decode(token)
      body = JWT.decode(token, ENV.fetch('JWT_ENCRYPTION_KEY', nil))[0]
      HashWithIndifferentAccess.new body
    rescue StandardError
      nil
    end
  end
end
