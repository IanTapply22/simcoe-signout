# frozen_string_literal: true

class AuthorizeApiRequest
  prepend SimpleCommand

  def initialize(cookies = {})
    @cookies = cookies
  end

  def call
    user
  end

  private

  def user
    @user ||= User.find(decoded_auth_token[:user_id]) if decoded_auth_token
    @user || errors.add(:token, 'Invalid token') && nil
  end

  def decoded_auth_token
    @decoded_auth_token ||= JsonWebToken.decode(cookie_auth_value)
  end

  def cookie_auth_value
    @cookies['auth_token'].presence || error!({ error: 'Missing token'})
  end
end
