# frozen_string_literal: true

class AddDisabledPeriodsToResources < ActiveRecord::Migration[7.0]
  def change
    add_column :resources, :disabledPeriods, :integer, array: true, default: []
  end
end
