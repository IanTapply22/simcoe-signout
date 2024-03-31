# frozen_string_literal: true

# Description: Gets all categories and excludes deleted ones
# Request URI: GET https://api.simcoesignout.com/api/core/categories
module Core
  module Categories
    class Get < Grape::API
      get do
        categories = Category.all

        error!({ error: 'Categories not found' }, 404) if categories.nil?

        response_categories = categories.reject { |category| category.deleted }.map do |category|

          {
            id: category.id,
            title: category.title,
            description: category.description
          }
        end

        present(response_categories)
      end
    end
  end
end
