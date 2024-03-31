# frozen_string_literal: true

module Admin
  module Users
    class Base < Grape::API
      prefix 'api/admin/users'

      mount Get
      mount Put
    end
  end
end
