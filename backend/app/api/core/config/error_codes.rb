# frozen_string_literal: true

module Core
  module Config
    class ErrorCodes
      ERROR_CODES = {
        test: 1000
      }.freeze

      def error_code(name)
        ERROR_CODES[name]
      end
    end
  end
end
