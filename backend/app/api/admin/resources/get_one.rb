# frozen_string_literal: true

# Description: Gets a resource with the specified ID
# Request URI: GET https://api.simcoesignout.com/api/admin/resources?id=:id
module Admin
  module Resources
    class GetOne < Grape::API
      params do
        requires :id, type: Integer
      end

      get ':id' do
        resource = Resource.find_by_id(params[:id])
        error!({ error: 'Resource not found' }, 404) if resource.nil?

        present(resource)
      end
    end
  end
end
