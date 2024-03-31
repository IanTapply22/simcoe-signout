<template>
    <v-table class="ml-10 mt-6 mr-10 rounded">
        <thead>
            <tr>
                <th class="text-left text-h5">
                    Title
                </th>
                <th class="text-left text-h5">
                    Description
                </th>
                <th class="text-left text-h5">
                    Deleted
                </th>
                <th class="text-left text-h5">
                    Actions
                </th>
            </tr>
        </thead>
        <tbody>
            <tr v-for="category in categories" :key="category.title">
                <td>{{ category.title }}</td>
                <td>{{ category.description }}</td>
                <td>{{ category.deleted }}</td>
                <td>
                    <v-btn color="red" class="mr-2" @click="deleteCategory(category.id)">
                        <v-icon>mdi-delete</v-icon> Delete
                    </v-btn>
                    <v-btn color="green" class="mr-2" @click="restoreCategory(category.id)">
                        <v-icon>mdi-restore</v-icon> Restore
                    </v-btn>
                </td>
            </tr>
        </tbody>
    </v-table>

    <createCategoryButton :categories="categories"/>
</template>
  
<script>
import { categoriesStore } from '@/stores/categories.ts'
import createCategoryButton from './createCategoryButton.vue'
import editCategoryButton from './editCategoryButton.vue'
export default {
    data() {
        return {
            categories: [],
            categoriesStore: categoriesStore()
        }
    },
    components: {
        createCategoryButton,
        editCategoryButton
    },
    methods: {
        /**
         * Deletes a category and fetches an updates list of categories
         * @param {*} id The ID of the category to delete
         */
        async deleteCategory(id) {
            await this.categoriesStore.deleteCategory(id);
            await this.categoriesStore.fetchCategoriesAdmin();
            this.categories = this.categoriesStore.getCategories;
        },
        async restoreCategory(id) {
            await this.categoriesStore.restoreCategory(id);
            await this.categoriesStore.fetchCategoriesAdmin();
            this.categories = this.categoriesStore.getCategories;
        }
    },
    async mounted() {
        await this.categoriesStore.fetchCategoriesAdmin();
        this.categories = this.categoriesStore.getCategories;
    }
}
</script>