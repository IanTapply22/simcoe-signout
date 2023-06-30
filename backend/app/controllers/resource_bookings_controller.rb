class ResourceBookingsController < ApplicationController
  before_action :set_resource_booking, only: %i[ show update destroy ]
  before_action :authenticate_admin, only: %i[index show update destroy]

  # GET /resource_bookings
  def index
    if params[:date]
      target_date = params[:date]
      @resource_bookings = ResourceBooking.select do |booking|
        booking.bookingDates.any? do |bd_string|
          bd_date = bd_string.match(/\"date\"=>\"([^"]+)\"/)&.captures&.first # Very goofy way to extract the date from the string
          booking_date = Date.parse(bd_date)
          booking_date == Date.parse(target_date)
        end
      end
    else
      @resource_bookings = ResourceBooking.all
    end
  
    render json: @resource_bookings
  end  
  
  # GET /resource_bookings/1
  def show
    render json: @resource_booking
  end

  # POST /resource_bookings
  def create
    @resource_booking = ResourceBooking.new(resource_booking_params)

    if @resource_booking.save
      render json: @resource_booking, status: :created, location: @resource_booking
    else
      render json: @resource_booking.errors, status: :unprocessable_entity
    end
  end

  # PATCH/PUT /resource_bookings/1
  def update
    if @resource_booking.update(resource_booking_params)
      render json: @resource_booking
    else
      render json: @resource_booking.errors, status: :unprocessable_entity
    end
  end

  # DELETE /resource_bookings/1
  def destroy
    @resource_booking.destroy
  end

  private
  
    # Use callbacks to share common setup or constraints between actions.
    def set_resource_booking
      @resource_booking = ResourceBooking.find(params[:id])
    end

    # Only allow a list of trusted parameters through.
    def resource_booking_params
      params.require(:resource_booking).permit(:id, :bookedBy, :resourceName, { bookingDates: [:date, :period] }, :destination, :comments)
    end    

    def authenticate_admin
      unless current_user && current_user.role == "administrator"
        render json: { error: 'User does not have permission to access this endpoint.' }, status: :forbidden
      end
    end  
end
