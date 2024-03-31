# frozen_string_literal: true

# Description: Creates a new category
# Request URI: POST https://api.simcoesignout.com/api/admin/categories
module Admin
  module Categories
    class Post < Grape::API
      desc 'Create a category'

      params do
        requires :category, type: Hash do
          requires :title, type: String
          requires :description, type: String
          optional :deleted, type: Boolean, default: false
        end
      end

      post do
        category = Category.new(params[:category])

        if Category.find_by_title(params[:category][:title])
          error!({ error: 'Category already exists with that name' }, 400)
        end

        if category.save
          category
        else
          error!({ error: category.errors.full_messages }, 400)
        end
      end
    end
  end
end
