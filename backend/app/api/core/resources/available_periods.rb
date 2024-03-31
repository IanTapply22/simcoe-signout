# frozen_string_literal: true

# Description: Gets the available periods for a resource
# Request URI: GET https://api.simcoesignout.com/api/core/resources/available_periods?id=:id
module Core
  module Resources
    class AvailablePeriods < Grape::API
      params do
        requires :id, type: Integer
      end

      get :available_periods do
        resource = Resource.find_by_id(params[:id])

        error!({ error: 'Resource not found' }, 404) if resource.nil?

        error!({ error: "Resource is either deleted or you don't have access to it" }, 403) if resource.deleted

        # TODO: Move this to the env file and make it configurable for both this and the frontend
        available_periods = [1, 2, 3, 4]

        # TODO: implement disabled periods for specific dates and periods
        disabled_periods = resource.disabledPeriods || []

        periods = available_periods - disabled_periods
        present(periods)
      end
    end
  end
end
