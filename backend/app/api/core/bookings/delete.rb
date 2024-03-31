# frozen_string_literal: true

# Description: Deletes, or cancels a booking by setting the deleted flag to true
# Request URI: DELETE https://api.simcoesignout.com/api/core/bookings?id=:id
module Core
  module Bookings
    class Delete < Grape::API
      params do
        requires :id, type: Integer
      end
      delete ':id' do
        resource_booking = ResourceBooking.find_by_id(params[:id])

        if resource_booking.bookedById != current_user.id
          error!({ error: 'You are not authorized to delete this booking' }, 403)
        end

        error!({ error: 'Booking not found' }, 404) if resource_booking.nil?

        error!({ error: 'Booking has already been deleted' }, 403) if resource_booking.deleted

        resource_booking.update(deleted: true)
      end
    end
  end
end
