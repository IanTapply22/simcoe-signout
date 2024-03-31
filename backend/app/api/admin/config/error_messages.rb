# frozen_string_literal: true

module Admin
  module Config
    class ErrorMessages
      ERROR_MESSAGES = {
        no_record_found_no_access: 'The record you are looking for does not exist or you do not have access to it'
      }.freeze

      def error_message(name)
        ERROR_MESSAGES[name]
      end
    end
  end
end
