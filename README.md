Flask Secure API with JWT & 2FA :
This API provides secure user authentication and product management using Flask, JWT authentication, and two-factor authentication (2FA) with Google Authenticator. It integrates with a MySQL database for user and product data storage.

Key Features :
User Registration & 2FA Setup
Users register with a hashed password.
A TOTP-based secret key is generated and encoded into a QR code for Google Authenticator.
Two-Factor Authentication (2FA) Verification
Users verify their OTP from Google Authenticator before login.
Login with JWT & 2FA
Users authenticate with username, password, and OTP.
A JWT token is issued upon successful login.
Product Management (JWT-Protected)
Create, Read, Update, Delete (CRUD) operations for products, accessible only with a valid JWT.

Security Measures :
JWT Authentication for secure session management.
Password Hashing using werkzeug.security.
2FA via Google Authenticator to prevent unauthorized logins.
Prepared Statements to prevent SQL Injection.

Testing :
Use Postman to send JSON requests for registration, 2FA verification, login, and CRUD product management.
