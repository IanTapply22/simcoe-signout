# frozen_string_literal: true

class CreateResources < ActiveRecord::Migration[7.0]
  def change
    create_table :resources do |t|
      t.string :name
      t.text :description
      t.string :location
      t.text :tags, array: true, default: []
      t.string :category

      t.timestamps
    end
  end
end
