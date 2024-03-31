# frozen_string_literal: true

class User < ApplicationRecord
  devise :omniauthable, omniauth_providers: [:google_oauth2]

  def self.create_from_provider_data(provider_data)
    user = User.where(uid: provider_data.uid).first

    return if user

    User.create(
      uid: provider_data.uid,
      email: provider_data.info.email
    )
  end

  def self.from_omniauth(auth)
    if auth.present? && (ENV.fetch('ALLOWED_EMAIL_DOMAINS').split(',').any? do |domain|
                           auth.info.email.end_with?(domain.strip)
                         end || ENV.fetch('ALLOWED_EMAILS').include?(auth.info.email))
      where(uid: auth.uid).first_or_create do |user|
        user.email = auth.info.email
        user.full_name = auth.info.name
        user.avatar_url = auth.info.image
      end
    else
      # Return nil if the auth object is nil or the email address is not valid
      nil
    end
  end

  def self.find_by_id(id)
    where(id: id).first
  end

  def self.find_by_full_name(full_name)
    where(full_name: full_name).first
  end
end
