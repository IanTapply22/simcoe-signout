# frozen_string_literal: true

# Description: Gets all users from the users database
# Request URI: GET https://api.simcoesignout.com/api/admin/users
module Admin
  module Users
    class Get < Grape::API
      get do
        users = User.all

        error!({ error: 'Users not found' }, 404) if users.nil?

        present(users)
      end
    end
  end
end
