# frozen_string_literal: true

class Resource < ApplicationRecord
  def find_by_id(id)
    where(id: id).first
  end

  def find_by_name(name)
    where(name: name, deleted: false).first
  end
end
