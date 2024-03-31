# frozen_string_literal: true

# Description: Deletes a booking from a specified ID
# Request URI: DELETE https://api.simcoesignout.com/api/admin/bookings/:id
module Admin
  module Bookings
    class Delete < Grape::API
      params do
        requires :id, type: Integer
      end

      delete ':id' do
        resource_booking = ResourceBooking.find_by_id(params[:id])
        error!({ error: 'Booking not found' }, 404) if resource_booking.nil?

        error!({ error: 'Booking has already been deleted' }, 403) if resource_booking.deleted

        resource_booking.update(deleted: true)
      end
    end
  end
end
