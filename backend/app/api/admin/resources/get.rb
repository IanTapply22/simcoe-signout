# frozen_string_literal: true

# Description: Gets all resources, even deleted ones
# Request URI: GET https://api.simcoesignout.com/api/admin/resources
module Admin
  module Resources
    class Get < Grape::API
      get do
        resources = Resource.all

        error!({ error: 'Resources not found' }, 404) if resources.nil?

        resources
      end
    end
  end
end
