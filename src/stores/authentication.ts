import router from '@/config/router';
import { getRequest, putRequest } from '@/utils/request';
import jwt_decode from 'jwt-decode';
import { defineStore } from 'pinia';

export const authenticationStore = defineStore({
  id: 'authentication',
  state: () => ({
    api_uri: `${import.meta.env.MODE === 'development' ? 'http://127.0.0.1:3000' : import.meta.env.MODE === 'staging' ? 'http://stgapi.simcoesignout.com' : 'https://api.simcoesignout.com'}/api/core/users`,
    admin_api_uri: `${import.meta.env.MODE === 'development' ? 'http://127.0.0.1:3000' : import.meta.env.MODE === 'staging' ? 'http://stgapi.simcoesignout.com' : 'https://api.simcoesignout.com'}/api/admin/users`,
    users: [],
  }),
  actions: {
    /**
     * Decodes a JWT to the raw JSON
     * @param jwt The JWT to decode
     * @returns The decoded and JSON formatted JWT
     */
    decodeJWT(jwt: string) {
      var decodedJWT = jwt_decode<DecodedJWT>(jwt);
      return decodedJWT;
    },
    /**
     * Gets all users from the API
     * @returns An array of all users and all data stored in the database
     */
    async getAllUsers() {
      const url = this.admin_api_uri
      this.users = await getRequest(url);
      return this.users;
    },
    /**
     * Requests the user data for the user that the JWT is stored for
     * @param auth_token The JWT auth token to use to request the user data 
     * @returns All user data for the user stored in the database
     */
    async requestUserData(auth_token: string) {
      try {
        const decodedJwt = this.decodeJWT(auth_token);
        const url = `${this.admin_api_uri}/${decodedJwt.user_id}`
        return await getRequest(url);
      } catch (error) {
        // Handle the case when the JWT is invalid or expired.
        console.error('Error decoding JWT:', error);
        return null;
      }
    },
    /**
     * Requests the user data for the person logged in
     * @param auth_token the auth token to authorize the requset with
     * @returns The user data for the person logged in
     */
    async requestMyUserData(auth_token: string) {
      if (!auth_token) {
        console.log('No auth token found')
        return null;
      }
  
      try {
        const decodedJwt = this.decodeJWT(auth_token);
        const url = `${this.api_uri}/${decodedJwt.user_id}`
        const data = await getRequest(url);
        return data;
      } catch (error) {
        // Handle the case when the JWT is invalid or expired.
        console.error('Error decoding JWT:', error);
        return null;
      }
    },
    /**
     * Updated a user with the specified ID
     * @param id The ID of the user to update
     * @param user The new data for the user
     * @param auth_token The auth token to authenticate the request with
     */
    async updateUser(id: number, user: User, auth_token: string) {
      try {
        const decodedJwt = this.decodeJWT(auth_token);
        const url = `${this.admin_api_uri}/${id}`
        const headers = {
          'Content-Type': 'application/json'
        }
        const body = JSON.stringify({
          user: {
            full_name: user.full_name,
            email: user.email,
            role: user.role,
            avatar_url: user.avatar_url,
          }
        })
        await putRequest(url, headers, body);

        if (id === decodedJwt.user_id) {
          if (user.role === 'member') {
            router.push({ name: 'Home' });
          }
        }
      } catch (error) {
        // Handle the case when the JWT is invalid or expired.
        console.error('Error decoding JWT:', error);
      }
    }
  },
})