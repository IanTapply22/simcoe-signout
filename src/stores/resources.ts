import { defineStore } from 'pinia'

export const resourcesPageStore = defineStore({
    id: 'resources',
    state: () => ({
        api_uri: 'http://[::1]:3000//resources',
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
    }),
    getters: {
        getCategories: (state) => state.categories,
        getFilteredCategories: (state) => state.filteredCategories,
        getAvailabilityTypes: (state) => state.availabilityTypes,
        getFilteredAvailabilityTypes: (state) => state.filteredAvailabilityTypes,
        getResources: (state) => state.resources,
        // Returns a resource based on its ID
        getResource: (state) => (id: string) => {
            return state.resources.find((r) => r.id === id);
        },
        // Returns a resources ID based on its name
        getResourceID: (state) => (name: string) => {
            const resource = state.resources.find((r) => r.name === name);
            return resource.id ? resource.id : '';
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
    },
    actions: {
        // Fetches all resources from the API
        async fetchResources() {
            const res = await fetch(this.api_uri)
            this.resources = await res.json();
        },
        setFilteredCategories(categories: string[]) {
            this.filteredCategories = categories;
        },
        setFilteredAvailabilityTypes(availabilityTypes: string[]) {
            this.filteredAvailabilityTypes = availabilityTypes;
        },
        removeCategoryFilter(category: string) {
            this.filteredCategories = this.filteredCategories.filter(c => !c.includes(category));
        },
        // Adds a new resource to the API
        async createResource(resource: Resource) {
            const res = await fetch(this.api_uri, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: resource.resourceName,
                    description: resource.resourceDescription,
                    location: resource.resourceLocation,
                    category: resource.resourceCategory,
                    tags: resource.resourceTags,
                })
            });

            const data = await res.json();

            if (!res.ok) {
                console.error('Error:', res.status);
                console.log('Response:', data);
                return;
            }

            this.resources.push(data);
        },
        // Updates a resource in the API
        async updateResource(id: string, resource: Resource) {
            const res = await fetch(`${this.api_uri}/${id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name: resource.resourceName,
                    description: resource.resourceDescription,
                    location: resource.resourceLocation,
                    tags: resource.resourceTags,
                    category: resource.resourceCategory,
                    id: id
                })
            });

            let data = await res.json();

            const resourceIndex = this.resources.findIndex(resource => resource.id === id);
            this.resources[resourceIndex] = data;
        },
        // Deletes a resource from the API
        async deleteResource(id: number) {
            await fetch(`${this.api_uri}/${id}`, {
                method: 'DELETE',
            })
            this.resources = this.resources.filter(resource => resource.id !== id);
        },
        // Deletes ALL resources from the API
        // USE THIS WITH CAUTION
        deleteAllResources() {
            for (const resource of this.resources) {
                this.deleteResource(resource.id);
            }
            this.resources = [];
        }
    }
})