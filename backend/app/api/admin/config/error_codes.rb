# frozen_string_literal: true

module Admin
  module Config
    class ErrorCodes
      ERROR_CODES = {
        no_record_found_no_access: 1000
      }.freeze

      def error_code(name)
        ERROR_CODES[name]
      end
    end
  end
end
