# frozen_string_literal: true

class AddBookedByIdToBookings < ActiveRecord::Migration[7.0]
  def change
    add_column :resource_bookings, :bookedById, :integer
  end
end
