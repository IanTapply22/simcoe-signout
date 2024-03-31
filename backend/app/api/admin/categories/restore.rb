# frozen_string_literal: true

# Description: Restores
# Request URI: PATCH https://api.simcoesignout.com/api/admin/categories/:id/restore
module Admin
    module Categories
      class Restore < Grape::API
        params do
          requires :id, type: Integer
        end
  
        route_param :id do
          put :restore do
            category = Category.find_by_id(params[:id])
  
            error!({ error: 'Category not found' }, 404) if category.nil?
  
            error!({ error: "Category is either already restored or you don't have access to it" }, 403) if category.deleted == false
  
            category.update(deleted: false)
          end
        end
      end
    end
  end
    