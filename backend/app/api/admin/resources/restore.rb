# frozen_string_literal: true

# Description: Restores
# Request URI: PATCH https://api.simcoesignout.com/api/admin/resources/:id/restore
module Admin
  module Resources
    class Restore < Grape::API
      params do
        requires :id, type: Integer
      end

      route_param :id do
        put :restore do
          resource = Resource.find_by_id(params[:id])

          error!({ error: 'Resource not found' }, 404) if resource.nil?

          error!({ error: "Resource is either already restored or you don't have access to it" }, 403) if resource.deleted == false

          resource.update(deleted: false)
        end
      end
    end
  end
end
  