class AddDeletedFlagToBookings < ActiveRecord::Migration[7.0]
  def up
    add_column :resource_bookings, :deleted, :boolean, default: false
  end

  def down
    remove_column :resource_bookings, :deleted
  end
end
