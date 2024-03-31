# frozen_string_literal: true

# Description: Deletes a resource with the specified ID
# Request URI: DELETE https://api.simcoesignout.com/api/admin/resources?id=:id
module Admin
  module Resources
    class Delete < Grape::API
      desc 'Delete a resource.'
      params do
        requires :id, type: Integer, desc: 'Resource ID.'
      end

      delete ':id' do
        resource = Resource.find_by_id(params[:id])
        error!({ error: 'Resource not found' }, 404) if resource.nil?

        error!({ error: 'Resource has already been deleted' }, 403) if resource.deleted

        resource.update(deleted: true)
      end
    end
  end
end
