# frozen_string_literal: true

# Description: Gets a user by ID, if the user is the current user or the current user is an administrator
# Request URI: GET https://api.simcoesignout.com/api/core/users?id=:id
module Core
  module Users
    class GetOne < Grape::API
      params do
        requires :id, type: Integer
      end

      get ':id' do
        user = User.find_by_id(params[:id])
        if current_user.id == params[:id]
          user
        elsif current_user.role == 'administrator'
          user
        else
          error!({ error: 'User not found' }, 404)
        end
      end
    end
  end
end
