# frozen_string_literal: true

# Description: Creates a resource
# Request URI: POST https://api.simcoesignout.com/api/admin/resources
module Admin
  module Resources
    class Post < Grape::API
      desc 'Create a resource.'

      params do
        requires :resource, type: Hash do
          requires :name, type: String
          requires :description, type: String
          requires :location, type: String
          requires :tags, type: Array do
            requires :text, type: String
            requires :colour, type: String
          end
          requires :category_id, type: String
        end
      end

      post do
        resource = Resource.new(params[:resource])

        if Resource.find_by_name(params[:resource][:name])
          error!({ error: 'Resource already exists with that name' }, 400)
        end

        if resource.save
          resource
        else
          error!({ error: resource.errors.full_messages }, 400)
        end
      end
    end
  end
end
