# frozen_string_literal: true

# Description: Updated a booking with the specified details
# Request URI: PUT https://api.simcoesignout.com/api/admin/bookings
module Admin
  module Bookings
    class Put < Grape::API
      params do
        requires :id, type: Integer
        requires :booking, type: Hash do
          requires :bookedBy, type: String
          requires :resource_id, type: Integer
          requires :bookingDates, type: Array do
            requires :date, type: String
            requires :period, type: Integer
          end
          requires :destination, type: String
          optional :comments, type: String
        end
      end

      put ':id' do
        # Find the booking by id
        resource_booking = ResourceBooking.find_by_id(params[:id])
        error!({ error: 'Resource booking not found' }, 404) unless resource_booking

        # Update the booking attributes
        resource_booking.assign_attributes(params[:booking])

        # Check for duplicate booking dates
        duplicate_dates = resource_booking.bookingDates.group_by do |bd|
                            [bd['date'], bd['period']]
                          end.select { |_, group| group.size > 1 }.keys
        error!({ error: 'Duplicate booking dates found' }, 422) if duplicate_dates.any?

        if resource_booking.deleted
          error!({ error: 'Booking has been deleted. Please rollback this booking to a non-deleted state' }, 403)
        end

        # TODO: Check if any other bookings exist for the same resource on the same date and period

        # Save the updated booking
        if resource_booking.save
          resource_booking
        else
          error!({ error: resource_booking.errors.full_messages.join(', ') }, 422)
        end
      end
    end
  end
end
