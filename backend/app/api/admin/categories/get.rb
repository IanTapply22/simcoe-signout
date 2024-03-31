# frozen_string_literal: true

# Description: Gets all categories and even includes deleted ones
# Request URI: GET https://api.simcoesignout.com/api/admin/categories
module Admin
  module Categories
    class Get < Grape::API
      get do
        categories = Category.all

        error!({ error: 'Categories not found' }, 404) if categories.nil?

        present(categories)
      end
    end
  end
end
