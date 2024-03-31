# frozen_string_literal: true

module Admin
  module Resources
    class Base < Grape::API
      prefix 'api/admin/resources'

      mount Get
      mount GetOne
      mount Post
      mount Delete
      mount Put
      mount Restore
    end
  end
end
