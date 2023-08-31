module Admin
    module Bookings
        class Base < Grape::API
            prefix 'api/admin/bookings'
  
            mount Get
            mount GetOne
            mount Post
            mount Delete
        end
    end
end