class AddDeletedFlagToCategories < ActiveRecord::Migration[7.0]
  def up
    add_column :categories, :deleted, :boolean, default: false
  end

  def down
    remove_column :categories, :deleted
  end
end
