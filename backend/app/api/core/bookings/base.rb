# frozen_string_literal: true

module Core
  module Bookings
    class Base < Grape::API
      prefix 'api/core/bookings'

      mount Get
      mount Post
      mount Delete
    end
  end
end
