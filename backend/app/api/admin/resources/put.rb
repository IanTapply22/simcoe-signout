# frozen_string_literal: true

# Description: Updates a resource with the specified ID
# Request URI: PUT https://api.simcoesignout.com/api/admin/resources
module Admin
  module Resources
    class Put < Grape::API
      params do
        requires :id, type: Integer
        requires :resource, type: Hash do
          requires :name, type: String
          requires :description, type: String
          requires :location, type: String
          requires :tags, type: Array do
            requires :text, type: String
            requires :colour, type: String
          end
          requires :category_id, type: Integer
        end
      end

      put ':id' do
        # Find the resource by name
        resource = Resource.find_by_id(params[:id])
        error!({ error: 'Resource not found' }, 404) unless resource

        error!({ error: 'Resource already exists with that ID' }, 400) if resource && resource.id != params[:id]

        # Update the resource attributes
        resource.assign_attributes(params[:resource])

        # Save the updated resource
        if resource.save
          resource
        else
          error!({ error: resource.errors.full_messages.join(', ') }, 422)
        end
      end
    end
  end
end
