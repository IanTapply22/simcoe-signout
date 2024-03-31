<template>
  <v-container>
    <v-row justify="center">
      <v-col cols="12" sm="8" md="4">
        <h1 class="text-center pt-15">
          <h2>Login</h2>
        </h1>

        <h2 class="text-center font-weight-light pt-12">A booking program for schools to book computer devices, rooms, and
          resources.</h2>
        <googleLoginButton class="mt-15" :click="openGoogleLoginPopup" />
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import googleLoginButton from '@components/authentication/googleLoginButton.vue';
import { authenticationStore } from '@/stores/authentication.ts';

export default {
  name: 'Login',
  data() {
    return {
      myData: null,
      authentication: authenticationStore(),
    };
  },
  components: {
    googleLoginButton
  },
  methods: {
    /**
     * Opens a popup window to the Google OAuth2 login page and listens for a message from the popup window
     * Once we've got confirmation of the token, route them to the home page, else show snackbar
     */
    openGoogleLoginPopup() {
      const apiURI = import.meta.env.MODE === 'development' ? 'http://127.0.0.1:3000' : import.meta.env.MODE === 'staging' ? 'https://stgapi.simcoesignout.com' : 'https://api.simcoesignout.com';
      var popup = window.open(`${apiURI}/users/auth/google_oauth2`, '_blank');

      const handleMessage = async (event) => {
        const authToken = this.$cookies.get('auth_token');
        if (authToken && authToken !== null) {
          window.removeEventListener('message', handleMessage);
          this.$router.push({ name: 'Home' });
        } else {
          this.displaySnackbarMessage('You are either not logged in or the account selected is not a DSBN (@dsbn.org) account.');
        }
      };

      window.addEventListener('message', handleMessage);
    },
    /**
     * Displays a message to the snackbar notifier
     * @param {} message The message to display in the snackbar
     */
    displaySnackbarMessage(message) {
      window.dispatchEvent(new CustomEvent("display-snackbar-message", {
        detail: {
          message: message
        }
      }))
    }
  },
};
</script>