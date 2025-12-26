# Fravix E-Library

Fravix is a Flask-based e-library web application that enables users to access, upload, and interact with digital learning resources.
It provides user authentication, email verification using OTP, resource uploads, ratings and comments, personalized recommendations, search functionality, notification system, chat and group conversations, subscription management, admin controls, and purchase request handling.

---

## Overview

Fravix allows users to create an account, verify it via email OTP, build profiles, browse and search educational resources, upload learning materials, join groups, chat with other users, receive notifications, and manage subscriptions.
Administrators can manage users and platform activities through an admin dashboard.

---

## Key Features

* User registration and login with secure authentication
* Email OTP verification for account activation
* User profiles with editing support
* Upload learning resources
* View, search, and filter resources
* Recommendations page
* Ratings, comments, and replies
* Favourite resources
* Profile view tracking
* Notification system with unread counts and history
* Real-time style chat messaging
* Group creation, editing, membership, and messaging
* Deleted message tracking
* Subscription system with plans and status page
* Product listing and purchase request flow
* Admin login and dashboard with user management
* Contact, FAQ, About, Terms & Conditions pages
* Error handling pages (404 and error view)
* Static uploads support

---

## Tech Stack

**Backend**

* Python
* Flask
* Flask-SQLAlchemy
* Flask-Login
* Flask-Bcrypt
* Flask-Session
* Flask-Mail

**Database**

* PostgreSQL

**Frontend**

* Jinja2 templates
* Static assets (CSS, images, media)

---

## Project Structure

```
Fravix-main/
├── app.py                     # Main Flask application
├── requirements.txt           # Python dependencies
├── ads.txt
│
├── static/                    # Static files
│   ├── images/                # Subscription images and resources
│   ├── logo, hero images
│   ├── 404 & error assets
│   └── notification sound
│
├── templates/                 # Jinja2 templates
│   ├── auth (login, register, verify, change password)
│   ├── profile & user pages
│   ├── resources pages
│   ├── chat & group pages
│   ├── subscription pages
│   ├── admin pages
│   ├── product & purchase pages
│   ├── informational pages
│   └── error pages
│
└── uploads/
    └── email.txt
```

---

## Installation

1. Extract the project.
2. Create and activate a virtual environment (recommended).
3. Install dependencies:

```
pip install -r requirements.txt
```

4. Ensure PostgreSQL is available and configured.
   Database connection is defined in `app.config['SQLALCHEMY_DATABASE_URI']` inside `app.py`.
5. Make sure the uploads folder exists:

```
uploads/
```

---

## Configuration

Application configuration is defined inside `app.py`, including:

* Database connection (PostgreSQL)
* Secret key
* Flask-Mail (Gmail SMTP)
* Session configuration
* Upload directory

OTP and notification emails use Flask-Mail Gmail SMTP configuration already included in the project.

---

## Running the Application

Run the development server:

```
python app.py
```

Then open in a browser:

```
http://127.0.0.1:5000/
```

---

## Usage

* Register an account
* Verify via email OTP
* Log in
* Edit your profile
* Browse and search resources
* Upload learning resources
* Comment, rate, and interact
* Join or create groups and chat
* View notifications
* Manage subscriptions
* Submit purchase requests if applicable
* Administrators can log in to the admin dashboard

---

## Subscription

Fravix includes subscription handling with:

* Subscription page
* Subscription status tracking

Plans and visuals are available under static images.

---

## Environment Notes

* PostgreSQL database credentials must be valid
* Gmail SMTP credentials must be valid for OTP and notifications
* Upload and static paths must exist

---

## License

No license file is included in this repository.

---

## Notes

* Database tables are created and managed using SQLAlchemy models.
* Notifications, chat, groups, and subscription functionality depend on database persistence.
* Uploaded files are stored under `static` or `uploads` depending on context.
