class AddDeletedFlagToResources < ActiveRecord::Migration[7.0]
  def up
    add_column :resources, :deleted, :boolean, default: false
  end

  def down
    remove_column :resources, :deleted
  end
end
