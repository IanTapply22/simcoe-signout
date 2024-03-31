interface ResourceBookingAdmin {
    bookedById: number;
    resource_id: number;
    bookingDates: BookingDate[];
    destination: string;
    comments: string;
}