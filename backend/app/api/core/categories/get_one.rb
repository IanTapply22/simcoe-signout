# frozen_string_literal: true

# Description: Gets a category with the specified ID and doesn't return one if it is deleted
# Request URI: GET https://api.simcoesignout.com/api/core/categories?id=:id
module Core
  module Categories
    class GetOne < Grape::API
      params do
        requires :id, type: Integer
      end
      get ':id' do
        category = Category.find_by_id(params[:id])
        error!({ error: 'Category not found' }, 404) if category.nil?

        error!({ error: "Category is either deleted or you don't have access to it" }, 403) if category.deleted

        present(category)
      end
    end
  end
end
