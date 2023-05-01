# Full-Stack Live Streaming Application

This is a full-stack live streaming application built with Flask as the backend and Vite + React as the frontend.

## Features

- Donations/subscriptions/payments using Stripe & cryptocurrency (primarily Dogecoin).
- Authentication using a crypto wallet, Google, or user login.
- Live streaming functionality using an adaptive streaming algorithm.

## Backend Setup

1. Create a new virtual environment: `python3 -m venv venv`
2. Activate the virtual environment: `source venv/bin/activate`
3. Install Flask and other required packages: `pip install flask stripe dogecoinapi`
4. Create a new Flask application and add routes for donations/subscriptions/payments, authentication, and live streaming.

## Frontend Setup

1. Create a new React application using Vite: `npm init vite@latest my-app --template react`
2. Install the required packages: `npm install react-router-dom axios react-stripe-elements @dogecoinapi/dogecoinapi`
3. Create the necessary components for the frontend pages and services.

Set up routes using react-router-dom.
Use axios to make HTTP requests to the Flask backend.
Integrate Stripe and Dogecoin API for donations/subscriptions/payments.
Getting Started
To get started, follow the steps below:

Clone this repository: git clone https://github.com/<your-username>/<your-repo>.git
Set up the backend as described in the Backend Setup section.
Set up the frontend as described in the Frontend Setup section.
Start the Flask server: python backend/app.py
Start the React app: cd frontend && npm start
Dependencies
The backend requires the following packages:

Flask
Stripe
DogecoinAPI
The frontend requires the following packages:

React
React Router DOM
Axios
React Stripe Elements
DogecoinAPI
Credits
This project was created by Nicolas Rodriguez. If you have any questions or suggestions, please contact me at nicolasmrodriguez3@gmail.com.

License
This project is licensed under the MIT License. See the LICENSE file for details.
