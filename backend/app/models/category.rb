# frozen_string_literal: true

class Category < ApplicationRecord
  def find_by_title(title)
    where(title: title, deleted: false).first
  end

  def find_by_id(id)
    where(id: id).first
  end
end
