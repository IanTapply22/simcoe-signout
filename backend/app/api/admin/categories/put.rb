# frozen_string_literal: true

# Description: Updates a category with the specified ID even if it's deleted
# Request URI: PUT https://api.simcoesignout.com/api/admin/categories
module Admin
  module Categories
    class Put < Grape::API
      params do
        requires :id, type: Integer
        requires :category, type: Hash do
          requires :title, type: String
          requires :description, type: String
        end
      end

      put ':id' do
        # Find the category by id
        category = Category.find_by_id(params[:id])
        error!({ error: 'Category not found' }, 404) unless category

        error!({ error: 'Category already exists with that name' }, 400) if category && category.id != params[:id]

        # Update the category attributes
        category.assign_attributes(params[:category])

        # Save the updated resource
        if category.save
          category
        else
          error!({ error: category.errors.full_messages.join(', ') }, 422)
        end
      end
    end
  end
end
