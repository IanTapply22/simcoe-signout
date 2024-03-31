# frozen_string_literal: true

class CreateResourceBookings < ActiveRecord::Migration[7.0]
  def change
    create_table :resource_bookings do |t|
      t.string :bookedBy
      t.string :resourceName
      t.jsonb :bookingDates, null: false, default: {}
      t.string :destination
      t.string :comments

      t.timestamps
    end
  end
end
