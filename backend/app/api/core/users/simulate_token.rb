# frozen_string_literal: true

# Description: Gets a token that can be used to simulate a user for requests. This is only available in development
# Request URI: GET https://api.simcoesignout.com/api/core/users/simulate_token
module Core
  module Users
    class SimulateToken < Grape::API

      get :simulate_token do
        user = User.find_by_id(1)
        if !user.present?
          error!({ error: 'User not found' }, 404)
        end

        auth_token = JsonWebToken.encode(user_id: user.id, user_full_name: user.full_name, user_role: user.role)
            # cookies[:auth_token] = {
            #     value: auth_token,
            #     domain: '127.0.0.1',
            #     expires: 60.minutes
            # }

        present(auth_token)
      end
    end
  end
end
  