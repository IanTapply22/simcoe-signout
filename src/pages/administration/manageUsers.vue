<template>
    <h1 class="mt-5 ml-10 mb-2">Manage Users</h1>
    <v-divider class="ml-10 mr-10"></v-divider>
    <userItems />
</template>

<script>
import { authenticationStore } from '@/stores/authentication.ts';
import userItems from './components/userItems.vue';

export default {
    components: {
        userItems
    }
}
</script>