# frozen_string_literal: true

# Description: Deletes, or cancels a booking by setting the deleted flag to true
# Request URI: POST https://api.simcoesignout.com/api/core/bookings
module Core
  module Bookings
    class Post < Grape::API
      params do
        requires :booking, type: Hash do
          requires :resource_id, type: Integer
          requires :bookingDates, type: Array do
            requires :date, type: String
            requires :period, type: Integer
          end
          optional :destination, type: String
          optional :comments, type: String
        end
      end

      post do
        resource_booking_params = params[:booking]
        resource_booking = ResourceBooking.new(resource_booking_params.merge(bookedBy: current_user.full_name,
                                                                             bookedById: current_user.id))

        if resource_booking.bookingDates.uniq! { |booking_date| [booking_date['date'], booking_date['period']] }
          error!({ error: 'Duplicate booking dates found' }, 422)
        elsif ResourceBooking.where(resource_id: resource_booking.resource_id, deleted: false).any? do |booking|
          booking.bookingDates.any? do |booking_date|
            resource_booking.bookingDates.any? do |new_booking_date|
              new_booking_date['date'] == booking_date['date'] && new_booking_date['period'] == booking_date['period']
            end
          end
        end
          error!({ error: 'Booking already exists for this resource on this date and period' }, 422)
        elsif resource_booking.save
          present(resource_booking)
        else
          error!({ error: resource_booking.errors.full_messages.join(', ') }, 422)
        end
      end
    end
  end
end
