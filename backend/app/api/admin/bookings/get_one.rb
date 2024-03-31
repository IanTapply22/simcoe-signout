# frozen_string_literal: true

# Description: Retrieves a booking from a specified ID. Disregards the deleted flag
# Request URI: GET https://api.simcoesignout.com/api/admin/bookings?id=:id
module Admin
  module Bookings
    class GetOne < Grape::API
      params do
        requires :id, type: Integer
      end

      get ':id' do
        resource_booking = ResourceBooking.find_by_id(params[:id])
        error!({ error: 'Booking not found' }, 404) if resource_booking.nil?

        present(resource_booking)
      end
    end
  end
end
