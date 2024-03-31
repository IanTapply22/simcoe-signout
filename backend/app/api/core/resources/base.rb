# frozen_string_literal: true

module Core
  module Resources
    class Base < Grape::API
      prefix 'api/core/resources'

      mount AvailablePeriods
      mount Get
      mount GetOne
    end
  end
end
