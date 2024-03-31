<template>
    <v-dialog v-model="bookingMenuOpen[index]" :close-on-content-click="false" location="end" width="500">
        <template v-slot:activator="{ props }">
            <v-btn class="mt-3 mb-1" color="green" variant="outlined" v-bind="props" @click="openBookingMenu(i)">
                <v-icon class="mr-3">mdi-book-open-page-variant</v-icon>
                <h3>Book Resource</h3>
            </v-btn>
        </template>

        <!-- BOOKING MENU -->
        <v-card min-width="300">
            <!-- Navigation buttons -->
            <v-list>
                <v-btn color="dark-grey" variant="flat" rounded="0" class="mt-0" @click="bookingPhaseIndex = 0" width="125">When</v-btn>
                <v-btn color="dark-grey" variant="flat" rounded="0" class="mt-0" width="125"
                    @click="bookingPhaseIndex = 1">Where</v-btn>
                <v-btn color="dark-grey" variant="flat" rounded="0" class="mt-0" width="125"
                    @click="bookingPhaseIndex = 2">Comments</v-btn>
                <v-btn color="dark-grey" variant="flat" rounded="0" class="mt-0" width="125"
                    @click="bookingPhaseIndex = 3">Review</v-btn>
            </v-list>
            <v-divider />

            <v-expand-transition>
                <v-card v-if="bookingPhaseIndex == 0" class="v-card--reveal">
                    <v-row class="text-center align-center justify-center">
                        <v-col class="py-5">
                            <h2 class="mb-2">{{ resource.name }}</h2>
                            <h5 class="mb-2">Period Identifiers</h5>
                            <div class="d-flex mx-auto ml-16 pl-7" width="200px">
                                <div class="d-flex align-items-center">
                                    <v-badge dot color="blue" class="pt-2">
                                    <v-icon size="x-large"></v-icon>
                                    </v-badge>
                                    <span class="ml-2"> = 1</span>
                                </div>
                                <div class="d-flex">
                                    <v-badge dot color="red" class="pt-2">
                                    <v-icon size="x-large"></v-icon>
                                    </v-badge>
                                    <span class="ml-2"> = 2</span>
                                </div>
                                <div class="d-flex">
                                    <v-badge dot color="green" class="pt-2">
                                    <v-icon size="x-large"></v-icon>
                                    </v-badge>
                                    <span class="ml-2"> = 3</span>
                                </div>
                                <div class="d-flex">
                                    <v-badge dot color="#c18900" class="pt-2">
                                    <v-icon size="x-large"></v-icon>
                                    </v-badge>
                                    <span class="ml-2"> = 4</span>
                                </div>
                            </div>

                            <VCalendar :attributes="attributes(resource.name)" is-dark="system" @dayclick="onDayClick" expanded />

                            <div v-if="selectedDates.length === 0">
                                <h5 class="my-10">Select a rental date to view availability</h5>
                            </div>
                            <!-- <div v-else class="ml-11">
                                <v-row>
                                    <v-col v-for="(item, index) in periods" :key="index">
                                        <v-checkbox
                                            v-model="selectedPeriods"
                                            :value="item"
                                            :label="item"
                                            :readonly="availablePeriodsForSelectedDate.indexOf(item) === -1"
                                            @click="(availablePeriodsForSelectedDate.indexOf(item) === -1) ? dispatchSnackbarMessageEvent() : false">
                                        </v-checkbox>
                                    </v-col>
                                </v-row>
                            </div> -->
                            <div v-else class="ml-11 mt-6">
                                <v-row>
                                    <v-col v-for="(item, index) in periods" :key="index">
                                        <v-checkbox
                                            v-model="selectedPeriods"
                                            :value="item"
                                            :label="item"
                                            :disabled="availablePeriodsForSelectedDate.indexOf(item) === -1"
                                            color="light-blue-accent-3"
                                            base-color="light-blue-accent-3"
                                            @click="(availablePeriodsForSelectedDate.indexOf(item) === -1) ? dispatchSnackbarMessageEvent() : false">
                                        </v-checkbox>
                                    </v-col>
                                </v-row>
                            </div>

                        </v-col>
                    </v-row>
                </v-card>
            </v-expand-transition>

            <v-expand-transition>
                <v-card v-if="bookingPhaseIndex == 1" class="v-card--reveal">
                    <v-text-field clearable class="ml-7 mt-4 mr-7 mb-3" hint="The destination it's going to (ex. 207D, 130)"
                        v-model="destination" label="Destination" :rules="[rules.required]" />
                </v-card>
            </v-expand-transition>

            <v-expand-transition>
                <v-card v-if="bookingPhaseIndex == 2" class="v-card--reveal">
                    <v-text-field clearable class="ml-7 mt-4 mb-4 mr-7" hint="Any comments regarding the booking"
                        v-model="comments" label="Comments" />
                </v-card>
            </v-expand-transition>

            <v-expand-transition>
                <v-card v-if="bookingPhaseIndex == 3" class="v-card--reveal ml-3 mt-3" max-width="350">
                    <h3>Selected Dates:</h3>
                    <v-chip v-for="date in selectedDates" :key="date.id" color="blue" class="mr-2 mt-2">{{ date.id }}</v-chip>
                    <h3 class="mt-2">Selected Periods: <span class="font-weight-regular">{{ selectedPeriods.sort().join(', ') }}</span></h3>
                    <h3 class="mt-2">Destination: <span class="font-weight-regular">{{ destination }}</span></h3>
                    <h3 class="mt-2 mb-3">Comments: <span class="font-weight-regular">{{ comments }}</span></h3>
                </v-card>
            </v-expand-transition>



            <!-- These are buttons/actions you can press/execute that are displayed on the bottom of the card -->
            <v-card-actions class="d-flex align-items-end">
                <v-spacer></v-spacer>
                <v-btn color="white" variant="text" @click="closeBookingMenu(index)">
                    Cancel
                </v-btn>
                <!-- Show if they aren't on the first tab -->
                <v-btn color="blue" v-if="bookingPhaseIndex != 0" variant="text" @click="previousPhase">
                    Back
                </v-btn>
                <!-- Show if they are on any other tab but the last one -->
                <v-btn color="blue" v-if="bookingPhaseIndex != 3" variant="text" @click="nextPhase">
                    Next
                </v-btn>
                <!-- Only show this is they are at the end of the booking process and are in the review phase -->
                <v-btn color="blue" variant="text" @click="bookResource(resource, index)">
                    Book
                </v-btn>
            </v-card-actions>
        </v-card>
    </v-dialog>

    <v-dialog v-model="showNoDatesSelectedDialog" max-width="500">
        <v-card>
            <v-card-title class="headline">No Dates Selected</v-card-title>
            <v-card-text>
                <h3>No dates have been selected! Please select a booking date.</h3>
            </v-card-text>
            <v-card-actions>
                <v-spacer></v-spacer>
                <v-btn color="green" text @click="showNoDatesSelectedDialog = false">Ok</v-btn>
            </v-card-actions>
        </v-card>
    </v-dialog>

    <v-dialog v-model="showNoPeriodSelectedDialog" max-width="500">
        <v-card>
            <v-card-title class="headline">No Period Selected</v-card-title>
            <v-card-text>
                <h3>No period was selected for your booking! Please select a period.</h3>
            </v-card-text>
            <v-card-actions>
                <v-spacer></v-spacer>
                <v-btn color="green" text @click="showNoPeriodSelectedDialog = false">Ok</v-btn>
            </v-card-actions>
        </v-card>
    </v-dialog>
</template>

<script>
import { resourcesPageStore } from '@/stores/resources';
import { bookingsStore } from '@/stores/bookings';
import { authenticationStore } from '@/stores/authentication';

const validPhases = ["when", "where", "comments", "review"];

export default {
    data: () => ({
        bookingsStore: bookingsStore(),
        authenticationStore: authenticationStore(),
        bookingMenuOpen: [],
        date: new Date(),
        bookingPhaseIndex: 0,

        selectedDates: [],
        selectedPeriods: [],
        destination: null,
        comments: null,

        periods: [1, 2, 3, 4],
        availablePeriodsForSelectedDateLoading: false,
        availablePeriodsForSelectedDate: [],

        showNoDatesSelectedDialog: false,
        showNoPeriodSelectedDialog: false,
        rules: {
            required: value => !!value || 'This field is required.',
        },
    }),
    props: {
        index: {
            type: Number,
            required: true,
        },
        resource: {
            type: Object,
            required: true,
        }
    },
    methods: {
        async refreshAvailablePeriods() {
            this.availablePeriodsForSelectedDateLoading = true
            await this.bookingsStore.getAvailablePeriodsForResourceOnDates(this.resource.id, this.resource.name, this.selectedDates.map(date => date.id))
            this.availablePeriodsForSelectedDateLoading = false

            this.availablePeriodsForSelectedDate = this.bookingsStore.availablePeriods

            // We updated our available periods. If the user had already selected one, then remove it
            // from the JS array
            this.selectedPeriods = this.selectedPeriods.filter(period => this.availablePeriodsForSelectedDate.includes(period))
        },
        /**
         * Resets all variables related to the booking process (phase index, selected dates, etc.)
        */
        resetAllVariables() {
            this.bookingPhaseIndex = 0;
            this.selectedDates = [];
            this.selectedPeriods = [];
            this.destination = null;
            this.comments = null;
        },
        /**
         * Opens the booking menu
         */
        openBookingMenu(index) {
            this.bookingMenuOpen[index] = true;
        },
        /**
         * Closes the booking menu
         */
        closeBookingMenu(index) {
            this.bookingMenuOpen[index] = false;
            this.resetAllVariables();
        },
        /**
         * Books the resource
         */
        async bookResource(resource, index) {
            if (this.selectedDates.length == 0) {
                this.showNoDatesSelectedDialog = true;
                return;
            }

            if (this.selectedPeriods.length === 0) {
                this.showNoPeriodSelectedDialog = true;
                return;
            }

            const bookingDates = [];
            try {
                const userData = await this.authenticationStore.requestMyUserData(this.$cookies.get('auth_token'));
                for (let i = 0; i < this.selectedDates.length; i++) {
                    for (let j = 0; j < this.selectedPeriods.length; j++) {
                        bookingDates.push({ date: this.selectedDates[i].id, period: this.selectedPeriods[j] });
                    }
                }
                this.bookingsStore.createBooking({
                    bookedBy: userData.full_name, // Don't worry, you can't spoof this ;)
                    resource_id: resource.id,
                    bookingDates: bookingDates,
                    destination: this.destination,
                    comments: this.comments,
                });
                this.resetAllVariables();
                this.closeBookingMenu(index);
            } catch (error) {
                // Handle the error appropriately
                console.error('Error occurred during booking:', error);
            }

            // wait 200ms for the booking to be created
            await new Promise(resolve => setTimeout(resolve, 200));

            await this.bookingsStore.fetchAllBookings();
        },
        /**
         * Move to next phase of booking
         */
        nextPhase() {
            if (this.bookingPhaseIndex < validPhases.length - 1) {
                this.bookingPhaseIndex++;
            }
        },
        /**
         * Move to previous phase of booking
         */
        previousPhase() {
            if (this.bookingPhaseIndex > 0) {
                this.bookingPhaseIndex--;
            }
        },
        /**
         * Get bookings in an array form for the calendar
         */
        getBookings(resourceName) {
            const bookings = [];

            this.bookingsStore.getBookingsForResource(resourceName).forEach(booking => {
                booking.bookingDates.forEach(bookingDate => {
                    let color = null;

                    // Set the color based on the bookingDate.period value
                    switch (bookingDate.period) {
                        case 1:
                            color = 'blue';
                            break;
                        case 2:
                            color = 'red';
                            break;
                        case 3:
                            color = 'green';
                            break;
                        case 4:
                            color = 'yellow';
                            break;
                        default:
                            break;
                    }

                    if (!booking.deleted) {
                    bookings.push({
                        resourceName: booking.resourceName,
                        period: bookingDate.period,
                        date: new Date(bookingDate.date),
                        bookerFirstName: booking.bookedBy.split(' ')[0],
                        bookerLastName: booking.bookedBy.split(' ')[1],
                        color: color,
                    });
                }
                });
            });

            return bookings;
        },
        async onDayClick(day) {
            // Date id is yyyy-mm-dd like 2023-09-04. Assigned by VCalendar
            const selectedDateIds = this.selectedDates.reduce((accumulator, date) => {
                accumulator[date.id] = true;
                return accumulator;
            }, {});

            if (!selectedDateIds[day.id]) {
                this.selectedDates.push({
                  id: day.id,
                  date: day.date,
                });
            } else {
                this.selectedDates = this.selectedDates.filter(date => date.id !== day.id);
            }

            this.refreshAvailablePeriods()
        },
        attributes(resourceName) {
            const bookings = this.getBookings(resourceName)
                                .sort((a, b) => {
                                    // Compare dates first
                                    const dateComparison = a.date.getTime() - b.date.getTime();

                                    // If the dates are the same, compare periods
                                    if (dateComparison === 0) {
                                        return a.period - b.period;
                                    }

                                    return dateComparison;
                                }) || [];

            const test = [
                // Pushing the current date to the front of the attributes array forces the calendar to open
                // on the current month
                {
                    dates: new Date()
                },

                // Also include any dates that we have manually clicked on. These will show up with a blue circle behind them
                ...this.selectedDates.map(date => ({
                    highlight: true,
                    dates: date.date
                })),

                // Finally, include all active bookings. This will draw the "period" dot under the date where appropriate and generate
                // the popover. I'm not sure how the library is doing the work to combine the popovers, but we have no control over it :(
                ...bookings
                    .map(booking => ({
                        dates: new Date(booking.date.getFullYear(), booking.date.getMonth(), booking.date.getDate() + 1),
                        dot: {
                            color: booking.color,
                            class: booking.isComplete ? "opacity-75" : "",
                        },
                        popover: {
                            label: booking.bookerLastName + ", " + booking.bookerFirstName + " - " + booking.resourceName + " (Period " + booking.period + ")",
                        },
                    })),
            ];

            return test;
        },

        dispatchSnackbarMessageEvent() {
            window.dispatchEvent(new CustomEvent("display-snackbar-message", {
                detail: {
                    message: "This period is unavailable on one of the dates you have selected. Please review your date selection to book this period!"
                }
            }))
        }
    },
    async mounted() {
        await this.bookingsStore.fetchAllBookings();
    }
}
</script>

<style>
.v-card--reveal {
    bottom: 0;
    opacity: 1 !important;
    position: absolute;
    width: 100%;
}

.flexcard {
    display: flex;
    flex-direction: column;
}
</style>