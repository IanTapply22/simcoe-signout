class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :omniauthable, omniauth_providers: [:google_oauth2]
  # def self.create_from_provider_data(provider_data)
  #   puts "provider_data: #{provider_data}"
  # end
  def self.create_from_provider_data(provider_data)
    user = User.where(provider: provider_data.provider, uid: provider_data.uid).first

    unless user
      user = User.create(
        provider: provider_data.provider,
        uid: provider_data.uid,
        email: provider_data.info.email,
        # additional attributes you want to set based on provider_data
      )
    end
  end

  def self.from_omniauth(auth)
    where(provider: auth.provider, uid: auth.uid).first_or_create do |user|
      user.email = auth.info.email
      # user.password = Devise.friendly_token[0, 20]
      user.full_name = auth.info.name # assuming the user model has a name
      user.avatar_url = auth.info.image # assuming the user model has an image
      # If you are using confirmable and the provider(s) you use validate emails,
      # uncomment the line below to skip the confirmation emails.
      # user.skip_confirmation!
    end
  end
end