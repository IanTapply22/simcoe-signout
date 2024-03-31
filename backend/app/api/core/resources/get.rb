# frozen_string_literal: true

# Description: Gets all resources and excludes deleted ones, also has a filter for available on date
# Request URI: GET https://api.simcoesignout.com/api/core/resources
module Core
  module Resources
    class Get < Grape::API
      params do
        optional :category_ids, type: String
        optional :available_on_date, type: String
      end

      get do
        resources = Resource.where(deleted: false)

        error!({ error: 'Resources not found' }, 404) if resources.nil?

        if params[:category_ids].present?
          categories = params[:category_ids].split(',')
          resources = resources.where(category_id: categories)
        end
        if params[:available_on_date].present?
          resources = resources.reject do |resource|
            bookings_on_date = ResourceBooking.get_bookings_for_resource_on_date(resource.id,
                                                                                 params[:available_on_date]).count
            bookings_on_date == 4
          end
        end
        resources
      end
    end
  end
end
