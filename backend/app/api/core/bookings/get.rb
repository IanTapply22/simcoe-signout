# frozen_string_literal: true

# Description: Gets all bookings but excludes deleted ones
# Request URI: GET https://api.simcoesignout.com/api/core/bookings
module Core
  module Bookings
    class Get < Grape::API
      params do
        optional :start_date, type: String
        optional :end_date, type: String
        optional :period, type: Integer
        optional :resource_id, type: Integer
        optional :only_mine, type: Boolean
      end

      get do
        if params[:start_date].present? && params[:end_date].present?
          start_date = Date.parse(params[:start_date])
          end_date = Date.parse(params[:end_date])

          @resource_bookings = ResourceBooking.select do |booking|
            booking.bookingDates.any? do |date|
              bd_date = date['date']
              booking_date = Date.parse(bd_date)
              booking_date >= start_date && booking_date <= end_date
            end
          end

          if params[:period]
            @resource_bookings = @resource_bookings.select do |booking|
              booking.bookingDates.any? do |date|
                date['period'] == params[:period]
              end
            end
          end

          if params[:resource_id].present?
            @resource_bookings = @resource_bookings.select do |booking|
              booking.resource_id == params[:resource_id]
            end
          end
        elsif params[:period].present?
          @resource_bookings = ResourceBooking.select do |booking|
            booking.bookingDates.any? do |date|
              date['period'] == params[:period]
            end
          end

          if params[:resource_id].present?
            @resource_bookings = @resource_bookings.select do |booking|
              booking.resource_id == params[:resource_id]
            end
          end
        elsif params[:resource_id].present?
          @resource_bookings = ResourceBooking.select do |booking|
            booking.resource_id == params[:resource_id]
          end
        else
          @resource_bookings = ResourceBooking.all

          if params[:only_mine] == true
            @resource_bookings = @resource_bookings.select do |booking|
              booking.bookedById == current_user.id
            end
          end
        end

        response = @resource_bookings.reject { |booking| booking.deleted }.map do |booking|

          {
            bookedBy: booking.bookedBy,
            resourceName: Resource.find_by_id(booking.resource_id).name,
            resource_id: booking.resource_id,
            bookingDates: booking.bookingDates
          }.tap do |hash|
            if params[:only_mine] == true
              hash[:id] = booking.id
              hash[:created_at] = booking.created_at
            end
          end
        end.compact

        present(response)
      end
    end
  end
end
