Wi-Fi Payment System API Documentation
Base URL
http://127.0.0.1:5000/

# summary

http://127.0.0.1:5000/admin/<int:admin_id> - POST/GET/PUT/DELETE
http://127.0.0.1:5000/admin/login' - POST
http://127.0.0.1:5000/admin/user/<int:user_id> - GET/POST/PUT/DELETE
http://127.0.0.1:5000/admin/hotspot/<int:hotspot_id> -GET/POST/PUT/DELETE
http://127.0.0.1:5000/admin/payment/<int:payment_id> -GET/POST/PUT/DELETE
http://127.0.0.1:5000/admin/bonus/user/<int:user_id> - GET/POST/PUT/DELETE
http://127.0.0.1:5000/user/login - POST
http://127.0.0.1:5000/user/payments - GET

1. User Authentication
Endpoint: /user/login
Method: POST
Description: Authenticate a user and return a JWT token.

Request Body:

json
{
    "phone_number": "0114455534",
    "password": "0114455534"
}
Response:

json
{
    "message": "Login successful",
    "status": "success",
    "token": "your_jwt_token"
}
2. Get User Payments
Endpoint: /user/payments
Method: GET
Description: Retrieve all payments made by the authenticated user.

Headers:

json
{
    "Authorization": "Bearer your_jwt_token"
}

3. Add Payment
Endpoint: /admin/payment
Method: POST
Description: Add a payment record to the system.

Request Body:

json
{
    "user_id": 1,
    "amount": 200.0,
    "hotspot_id": 3
}

4. Update Payment
Endpoint: /admin/payment/<payment_id>
Method: PUT
Description: Update an existing payment record.

Request Body:

json
{
    "user_id": 1,
    "amount": 300.0,
    "hotspot_id": 2
}
Response:

json
{
    "message": "Payment updated successfully",
    "status": "success",
    "payments": [
        {
            "payment_id": 1,
            "user_id": 1,
            "amount": 300.0,
            "hotspot_id": 2,
            "timestamp": "2024-12-01T14:00:00"
        }
    ]
}
5. Get All Payments
Endpoint: /admin/payments
Method: GET
Description: Retrieve all payments in the system (Admin only).

Headers:

json
{
    "Authorization": "Bearer your_admin_jwt_token"
}

6. Manage Hotspots
Endpoint: /admin/hotspot
Method: POST
Description: Add a new hotspot.

Request Body:

json
{
    "hotspot_name": "Main Campus Wi-Fi",
    "router_mac": "00:1A:2B:3C:4D:5E",
    "admin_id": 1
}

7. Admin Login
Endpoint: /admin/login
Method: POST
Description: Authenticate an admin user and return a JWT token.

Request Body:

json
{
    "name": "admin",
    "email": "admin@gmail.com"
    "password": "admin123"
}

8. Manage Users
Endpoint: /admin/user
Method: POST
Description: Add a new user.

Request Body:

{
    "phone_number": "0114455534",
}
