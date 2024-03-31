# frozen_string_literal: true

module Admin
  module Bookings
    class Base < Grape::API
      prefix 'api/admin/bookings'

      mount Get
      mount GetOne
      mount Post
      mount Delete
      mount Put
    end
  end
end
