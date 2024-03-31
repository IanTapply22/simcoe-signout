# frozen_string_literal: true

# Description: Updates a users information
# Request URI: PUT https://api.simcoesignout.com/api/admin/users
module Admin
  module Users
    class Put < Grape::API
      params do
        requires :id, type: Integer
        requires :user, type: Hash do
          requires :full_name, type: String
          requires :email, type: String
          requires :role, type: String
          requires :avatar_url, type: String
        end
      end

      put ':id' do
        # Find the user by id
        user = User.find_by_id(params[:id])
        error!({ error: 'User not found' }, 404) unless user

        # Update the user attributes
        user.assign_attributes(params[:user])

        # Save the updated user
        if user.save
          user
        else
          error!({ error: user.errors.full_messages.join(', ') }, 422)
        end
      end
    end
  end
end
