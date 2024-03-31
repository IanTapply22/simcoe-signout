import { deleteRequest, getRequest, postRequest, putRequest } from '@/utils/request';
import { defineStore } from 'pinia'

export const categoriesStore = defineStore({
    id: 'categories',
    state: () => ({
        api_uri: `${import.meta.env.MODE === 'development' ? 'http://127.0.0.1:3000' : import.meta.env.MODE === 'staging' ? 'http://stgapi.simcoesignout.com' : 'https://api.simcoesignout.com'}/api/core/categories`,
        admin_api_uri: `${import.meta.env.MODE === 'development' ? 'http://127.0.0.1:3000' : import.meta.env.MODE === 'staging' ? 'http://stgapi.simcoesignout.com' : 'https://api.simcoesignout.com'}/api/admin/categories`,
        categories: [] as Category[],
        categoryNames: [] as string[],
    }),
    getters: {
        getCategoryId: (state) => (categoryName: string) => {
            const category = state.categories.find(category => category.title === categoryName);
            return category ? category.id : -1;
        },
        getCategories: (state) => state.categories,
        getCategoryNames: (state) => state.categoryNames,
        // get all category Ids based off of what what category names are provided
        getCategoryIds: (state) => (categoryNames: string[]) => {
            const categories = state.categories;
            const categoryIds: number[] = [];

            categoryNames.forEach(categoryName => {
                const category = categories.find(category => category.title === categoryName);
                if (category) {
                    categoryIds.push(category.id);
                }
            });

            return categoryIds;
        },
    },
    actions: {
        getCategoryName (categoryId: number) {
            const category = this.categories.find(category => category.id === categoryId);
            return category ? category.title : '';
        },
        /**
         * Fetches all categories from the via the administrator API (all data)
         */
        async fetchCategoriesAdmin() {
            const url = `${this.admin_api_uri}`
            this.categories = await getRequest(url);
        },
        /**
         * Fetches all categories from the via the core API (names only)
         */
        async fetchCategoriesCore() {
            const url = `${this.api_uri}`
            this.categories = await getRequest(url);
        },
        /**
         * Fetches all category names of resources
         */
        async fetchCategoryNames() {
            const url = `${this.api_uri}`
            const fetchedCateogires = await getRequest(url);

            this.categoryNames = fetchedCateogires.map((category: Category) => {
                return category.title;
            });
        },
        /**
         * Creates a new category
         * @param category The category to create (title and description)
         */
        async createCategory(category: Category) {
            const url = this.admin_api_uri
            const headers = {
                'Content-Type': 'application/json'
            }
            const body = JSON.stringify({
                category: {
                    title: category.title,
                    description: category.description
                }
            })

            const newCategory: Category = await postRequest(url, headers, body);
            this.categories = this.categories.concat(newCategory);
        },
        /**
         * Updates a categories details (title and description)
         * @param id The ID of the category to update
         * @param category The category object that has the data
         */
        async updateCategory(id: number, category: Category) {
            const url = `${this.admin_api_uri}/${id}`
            const headers = {
                'Content-Type': 'application/json'
            }
            const body = JSON.stringify({
                category: {
                    title: category.title,
                    description: category.description,
                    id: id
                }
            })

            let newCategory = await putRequest(url, headers, body);

            const resourceIndex = this.categories.findIndex(category => category.id === id);
            this.categories[resourceIndex] = newCategory;
        },
        /**
         * Deletes a category from the database and from the store
         * @param id The ID of the category to delete
         */
        async deleteCategory(id: number) {
            const url = `${this.admin_api_uri}/${id}`
            await deleteRequest(url);
            this.categories = this.categories.filter(resource => resource.id !== id);
        },
        async restoreCategory(id: number) {
            const url = `${this.admin_api_uri}/${id}/restore`
            const headers = {
                'Content-Type': 'application/json'
            }
            const body = JSON.stringify({})
            await putRequest(url, headers, body);
        }
    }
})