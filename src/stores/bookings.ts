import { defineStore } from 'pinia';
import { resourcesPageStore } from './resources';
import { deleteRequest, getRequest, postRequest } from '@/utils/request';

export const bookingsStore = defineStore({
    id: 'bookings',
    state: () => ({
        api_uri: `${import.meta.env.MODE === 'development' ? 'http://127.0.0.1:3000' : import.meta.env.MODE === 'staging' ? 'https://stgapi.simcoesignout.com' : 'https://api.simcoesignout.com'}/api/core/bookings`,
        admin_api_uri: `${import.meta.env.MODE === 'development' ? 'http://127.0.0.1:3000' : import.meta.env.MODE === 'staging' ? 'https://stgapi.simcoesignout.com' : 'https://api.simcoesignout.com'}/api/admin/bookings`,
        validPeriods: [1, 2, 3, 4],
        bookings: [] as any[],

        filteredPeriods: [1, 2, 3, 4],
        filteredDateFrom: new Date(new Date().getFullYear(), new Date().getMonth() - 2, new Date().getDate()).toISOString().slice(0, 10),
        filteredDateTo: new Date().toISOString().slice(0, 10),
        filteredResourceName: '',
        filteredResourceId: -1,

        availablePeriods: [] as number[],
    }),
    getters: {
        getValidPeriods: (state) => state.validPeriods,
        getBookings: (state) => state.bookings,
        getBookingsForResourceOnDate: (state) => (resourceName: string, date: string) => {
            const bookings = state.bookings.filter((booking: any) => booking.resourceName === resourceName);
            const filteredBookings = bookings.filter((booking: any) => booking.bookingDates.find((bookingDate: any) => bookingDate.date === date));
            return filteredBookings;
        },
        getBookingsForResource: (state) => (resourceName: string) => {
            const bookings = state.bookings.filter((booking: any) => booking.resourceName === resourceName);
            return bookings;
        }
    },
    actions: {
        /**
         * Fetches all bookings from the API with the specified filters
         */
        async fetchBookings() {
            // convert the filtered resource name to an ID
            const resourcesPage = resourcesPageStore();
            await resourcesPage.fetchAllResources();
            const filteredResource: any = resourcesPage.resources.find((r) => r.name === this.filteredResourceName);
            if (filteredResource) {
                this.filteredResourceId = filteredResource.id;
            }
            let url = `${this.admin_api_uri}?period=${this.filteredPeriods}&resource_id=&start_date=${this.filteredDateFrom}&end_date=${this.filteredDateTo}`;
            if (this.filteredResourceId !== -1) {
                url += `&resource_id=${this.filteredResourceId}`;
            }
            this.bookings = await getRequest(url);
        },
        /**
         * Fetches all bookings from the API without any filters applied
         */
        async fetchAllBookings() {
            const url = this.api_uri
            this.bookings = await getRequest(url);
        },
        /**
         * Fetches all of the bookings for the user that is currently logged in
         */
        async fetchMyBookings() {
            const url = `${this.api_uri}?only_mine=true`
            this.bookings = await getRequest(url);
        },
        /**
         * Fetches all bookings that were made on the specified date
         * @param date The date to fetch bookings for
         * @returns The bookings for the specified date
         */
        async fetchBookingsForDate(date: string) {
            const url = `${this.api_uri}?date=${date}`
            return await getRequest(url);
        },
        /**
         * Creates a new booking for a resource
         * @param booking The booking to create
         */
        async createBooking(booking: ResourceBooking) {
            const url = this.api_uri
            const headers = {
                'Content-Type': 'application/json'
            }
            const body = JSON.stringify({
                booking: {
                    bookedBy: booking.bookedBy,
                    resource_id: booking.resource_id,
                    bookingDates: booking.bookingDates,
                    destination: booking.destination,
                    comments: booking.comments,
                }
            })
            const newBooking = await postRequest(url, headers, body);
            this.bookings.push(newBooking);
        },
        /**
         * Deletes a booking from an administrator standpoint through the admin API
         * @param id The ID of the booking to delete
         */
        async deleteBooking(id: string) {
            const url = `${this.admin_api_uri}/${id}`
            await deleteRequest(url);
            this.bookings = this.bookings.filter((booking: any) => booking.id !== id);
        },
        /**
         * Deletes a booking from a user standpoint through the core API
         * @param id The ID of the booking to delete
         */
        async deleteMyBooking(id: string) {
            const url = `${this.api_uri}/${id}`
            await deleteRequest(url);
            this.bookings = this.bookings.filter((booking: any) => booking.id !== id);
        },
        /**
         * Deletes all of the bookings for the current logged in user
         * FOR DEVELOPMENT ONLY
         */
        async deleteAllMyBookings() {
            await this.fetchMyBookings();
            this.bookings.forEach(async (booking: any) => {
                await this.deleteMyBooking(booking.id);
            })
        },
        /**
         * Gets the available periods that a user can book for the specified dates
         * @param id The ID of the resource to get the available periods for
         * @param resourceName The name of the resource to get the available periods for
         * @param dates The dates to get the available periods for
         */
        async getAvailablePeriodsForResourceOnDates(id: number, resourceName: string, dates: string[]) {
            // Get all periods for the resource
            await resourcesPageStore().fetchAvailablePeriodsForResource(id);

            // Get all bookings for the resource
            const bookings = this.bookings.filter((booking: any) => booking.resourceName === resourceName);

            // Filter bookings that overlap with any of the dates
            const overlappingBookings = bookings.filter((booking: any) => {
                const overlappingDates = booking.bookingDates.filter((bookingDate: any) => dates.includes(bookingDate.date));
                return overlappingDates.length > 0;
            });

            // Get all periods that are not booked on any of the dates
            const availablePeriods = resourcesPageStore().availablePeriods.filter((period: number) => {
                const overlappingBookingsForPeriod = overlappingBookings.filter((booking: any) => booking.bookingDates.find((bookingDate: any) => bookingDate.period === period));
                return overlappingBookingsForPeriod.length === 0;
            });

            this.availablePeriods = availablePeriods;
        }
    },
})