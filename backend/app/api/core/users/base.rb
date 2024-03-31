# frozen_string_literal: true

module Core
  module Users
    class Base < Grape::API
      prefix 'api/core/users'

      mount GetOne
      # mount SimulateToken
    end
  end
end
