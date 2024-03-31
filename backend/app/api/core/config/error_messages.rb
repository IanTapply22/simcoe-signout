# frozen_string_literal: true

module Core
  module Config
    class ErrorMessages
      ERROR_MESSAGES = {
        test: 1000
      }.freeze

      def error_message(name)
        ERROR_CODES[name]
      end
    end
  end
end
