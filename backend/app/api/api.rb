# frozen_string_literal: true

class Api < Grape::API
  mount Admin::Root
  mount Core::Root
end
