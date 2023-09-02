# Simcoe Signout
A private, bookings manager used to book devices, tools, and other resources through an online dashboard.

# Development Environment
The development environment looks to create a consistent devlopment experience across all devices. It can be setup by doing the following:

## Linux
1. Use the `cd` command to navigate to the root of this project
2. Install docker-compose via your Linux installs package manager
3. Update the `.env.local` file with the correct environment variables
4. Run `docker-compose up` to run docker-compose with a `tail` watching the log, or `docker-compose up -d` to silently start the dev server
5. Navigate to `127.0.0.1:5173` in your browser to access the frontend, or `127.0.0.1:3000` to access the API

Note, there is currently a bug. The node_modules folder that was generated by docker belongs to root:root. If you want to add any new packages you will need to `chown` that folder with `sudo chown -R $(whoami) node_modules` to ensure that you are the proper owner.
Note #2, you can also use this method on Windows but it is significantly slower than running it natively.

## Windows
1. Install yarn via NPM, rails (version specified in backend GemFile), and ruby (version specified in backend GemFile)
2. Open the project folder in your IDE of choice
3. Install the packages for the frontend by running the `yarn` command in the root of the directory, and install the Gems for the backend by running `bundle` in the `backend` directory
4. Use the `yarn run dev` command in the root and `rails s` in the `backend` directory to start both components of the project
