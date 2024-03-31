# frozen_string_literal: true

class ResourceBooking < ApplicationRecord
  def self.find_by_id(id)
    where(id: id).first
  end

  def self.update(id, booking)
    # Find the booking with the given id
    booking_to_update = find_by_id(id)

    # Save the updated booking
    if booking_to_update.update(booking)
      # Return the updated booking
      booking_to_update
    else
      # Return an error message if the booking could not be updated
      error!('Booking could not be updated', 500)
    end
  end

  def self.get_bookings_for_resource_on_date(resourceId, date)
    # Find all bookings for the given resource
    bookings = where(id: resourceId)

    # Find all bookings that contain the given date
    bookings.select do |booking|
      booking.bookingDates.any? do |bookingDate|
        bookingDate['date'] == date
      end
    end
  end
end
