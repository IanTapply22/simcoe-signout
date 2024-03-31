import { defineStore } from 'pinia'
import { bookingsStore } from './bookings';
import { categoriesStore } from './categories';
import { deleteRequest, getRequest, postRequest, putRequest } from '@/utils/request';

export const resourcesPageStore = defineStore({
    id: 'resources',
    state: () => ({
        api_uri: `${import.meta.env.MODE === 'development' ? 'http://127.0.0.1:3000' : import.meta.env.MODE === 'staging' ? 'http://stgapi.simcoesignout.com' : 'https://api.simcoesignout.com'}/api/core/resources`,
        admin_api_uri: `${import.meta.env.MODE === 'development' ? 'http://127.0.0.1:3000' : import.meta.env.MODE === 'staging' ? 'http://stgapi.simcoesignout.com' : 'https://api.simcoesignout.com'}/api/admin/resources`,
        categories: [
            'Category 1',
            'Category 2',
        ],
        filteredCategories: [] as string[],
        availabilityTypes: [
            'Available',
            'Unavailable',
        ],
        filteredAvailabilityTypes: [] as string[],
        resources: [] as any[],
        filteredDate: new Date(),

        availablePeriods: [] as number[],

        filteredFromDate: new Date(new Date().getFullYear(), new Date().getMonth() - 2, new Date().getDate()).toISOString().slice(0, 10),
        filteredToDate: new Date().toISOString().slice(0, 10),

        resourceNames: [] as string[],
    }),
    getters: {
        getCategories: (state) => state.categories,
        getFilteredCategories: (state) => state.filteredCategories,
        getAvailabilityTypes: (state) => state.availabilityTypes,
        getFilteredAvailabilityTypes: (state) => state.filteredAvailabilityTypes,
        getResources: (state) => state.resources,
        getDeletedResources: (state) => {
            return state.resources.filter((r) =>
                r.deleted === true
            );
        },
        getUndeletedResources: (state) => {
            return state.resources.filter((r) =>
                r.deleted === false
            );
        },
        // Returns a resource based on its ID
        getResource: (state) => (id: string) => {
            return state.resources.find((r) => r.id === id);
        },
        // Returns a resources ID based on its name
        getResourceID: (state) => (name: string) => {
            const resource = state.resources.find((r) => r.name === name);
            return resource ? resource.id : '';
        },
        // Returns a list of resources that have one of the filtered categories
        // If there are none, it just returns all of them
        getResourcesByFilteredCategories: (state) => {
            if (state.filteredCategories.length === 0) {
                return state.resources;
            } else {
                return state.resources.filter((r) =>
                    state.filteredCategories.includes(r.category)
                );
            }
        },
        getAvailableResourcesOnDate: (state) => (date: string) => {
            const bookingStore = bookingsStore();
            const resources = state.resources;

            const previousDate = new Date(date);
            previousDate.setDate(previousDate.getDate() - 1);

            const availableResources = resources.filter((resource: any) => {
                const bookingsOnDate = bookingStore.getBookings.filter((booking: any) => {
                    return booking.resourceName === resource.name && booking.bookingDates.some((bookingDate: any) => {
                        return bookingDate.date === previousDate.toISOString().slice(0, 10);
                    });
                });
                return bookingsOnDate.length <= 3;
            });

            return availableResources;
        }
    },
    actions: {
        async getResourceNameFromId(id: number) {
            await this.fetchAllResources();
            const resource = this.resources.find((resource: any) => resource.id === id);
            return resource ? resource.name : '';
        },
        /**
         * Fetches resources available on a date and that fall under the filtered categories
         * @param date The date to get available resources for
         */
        async fetchResources(date: String) {
            await categoriesStore().fetchCategoriesCore();
            const categoryIds = categoriesStore().getCategoryIds(this.filteredCategories);

            const url = `${this.api_uri}?category_ids=${categoryIds}&available_on_date=${date}`

            this.resources = await getRequest(url)
        },
        async fetchAllResources() {
            const url = `${this.api_uri}?categories=&available_on_date=`

            this.resources = await getRequest(url);
        },
        async fetchAllResourcesAdmin() {
            const url = `${this.admin_api_uri}`

            this.resources = await getRequest(url);
        },
        /**
         * Fetches all resources names
         */
        async fetchAllResourceNames() {
            const url = `${this.api_uri}?categories=&available_on_date=`

            const resourceNames = await getRequest(url);
            this.resourceNames = resourceNames.map((resource: any) => resource.name);
        },
        /**
         * Fetches all available periods for a resource that it can be booked for
         * @param id The ID of the resource to fetch available periods for
         */
        async fetchAvailablePeriodsForResource(id: number) {
            const url = `${this.api_uri}/available_periods?id=${id}`

            const availablePeriods = await getRequest(url);
            this.availablePeriods = availablePeriods;
        },
        /**
         * Adds categories to filter resources by
         * @param categories An array of category names as a string
         */
        setFilteredCategories(categories: string[]) {
            this.filteredCategories = categories;
            this.fetchResources(this.filteredDate.toISOString().slice(0, 10));
        },
        /**
         * Adds availability types to filter resources by
         * @param availabilityTypes An array of availability types as a string
         */
        setFilteredAvailabilityTypes(availabilityTypes: string[]) {
            this.filteredAvailabilityTypes = availabilityTypes;
        },
        /**
         * Removes a category name from the filter
         * @param category The category to add to remove from the filter
         */
        removeCategoryFilter(category: string) {
            this.filteredCategories = this.filteredCategories.filter(c => !c.includes(category));
        },
        /**
         * Creates a new resource in the API
         * @param resource The object of a resource that withholds all of the data
         */
        async createResource(resource: Resource) {
            const url = `${this.admin_api_uri}`
            const headers = {
                'Content-Type': 'application/json'
            }
            const body = JSON.stringify({
                resource: {
                    name: resource.resourceName,
                    description: resource.resourceDescription,
                    location: resource.resourceLocation,
                    category_id: resource.categoryId,
                    tags: resource.resourceTags,
                }
            })

            const resources = await postRequest(url, headers, body);
            this.resources.push(resources);
        },
        /**
         * Updates a resources information
         * @param id The ID of the resource to update
         * @param resource The new object of the resource that has all of the data
         */
        async updateResource(id: string, resource: Resource) {
            const url = `${this.admin_api_uri}/${id}`
            const headers = {
                'Content-Type': 'application/json'
            }
            const body = JSON.stringify({
                resource: {
                    name: resource.resourceName,
                    description: resource.resourceDescription,
                    location: resource.resourceLocation,
                    tags: resource.resourceTags,
                    //category: resource.resourceCategory,
                    category_id: resource.categoryId,
                    id: id
                }
            })

            const resources = await putRequest(url, headers, body);

            const resourceIndex = this.resources.findIndex(resource => resource.id === id);
            this.resources[resourceIndex] = resources;
        },
        /**
         * Deletes a resource
         * @param id The ID of the resource to delete
         */
        async deleteResource(id: number) {
            const url = `${this.admin_api_uri}/${id}`
            await deleteRequest(url);
            // add the deleted flag to the deleted resource in the resources array 
            const resourceIndex = this.resources.findIndex(resource => resource.id === id);
            this.resources[resourceIndex].deleted = true;
        },
        async restoreResource(id: number) {
            const url = `${this.admin_api_uri}/${id}/restore`
            const headers = {
                'Content-Type': 'application/json'
            }
            const body = JSON.stringify({})
            await putRequest(url, headers, body);
            // remove the deleted flag from the resource in the resources array
            const resourceIndex = this.resources.findIndex(resource => resource.id === id);
            this.resources[resourceIndex].deleted = false;
        },
        /**
         * USE WITH CAUTION. Deletes all resources from the API and from the store
         */
        deleteAllResources() {
            for (const resource of this.resources) {
                this.deleteResource(resource.id);
            }
            this.resources = [];
        }
    }
})