# frozen_string_literal: true

# Description: Deletes a category with the specified ID
# Request URI: DELETE https://api.simcoesignout.com/api/admin/categories?id=:id
module Admin
  module Categories
    class Delete < Grape::API
      params do
        requires :id, type: Integer
      end
      delete ':id' do
        category = Category.find_by_id(params[:id])
        error!({ error: 'Category not found' }, 404) if category.nil?

        error!({ error: 'Category has already been deleted' }, 403) if category.deleted

        category.update(deleted: true)
      end
    end
  end
end
