# frozen_string_literal: true

module Admin
  module Categories
    class Base < Grape::API
      prefix 'api/admin/categories'

      mount Get
      mount Post
      mount Delete
      mount Put
      mount Restore
    end
  end
end
