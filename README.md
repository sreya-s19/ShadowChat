# ShadowChat ⚡


ShadowChat is a secure, real-time, text-only messaging application built with Python, Flask, and WebSockets. Designed with a focus on privacy and cybersecurity principles, it provides an intuitive chat experience while serving as an educational tool for concepts like end-to-end encryption and threat detection.

## ✨ Core Features

*   **⚡ Real-Time Messaging:** Instant message delivery, typing indicators, and live online presence powered by **Flask-SocketIO**.
*   **🔐 Secure Authentication:** Robust user registration and login system with strong password hashing (**bcrypt**) and secure session management.
*   **🔑 Interactive Encryption Simulation:** Messages can be sent encrypted. The UI displays the ciphertext and allows users to manually decrypt it, making the concept of encryption tangible.
*   **🔬 Cybercrime Keyword Alerts:** A built-in system flags messages containing suspicious keywords (e.g., "password", "hack") with a visual alert, simulating a threat detection system.
*   **🎨 Modern & Polished UI:** A sleek, dark-themed, and responsive user interface inspired by modern chat applications.
*   **🔒 Input Sanitization:** All message inputs are sanitized using `bleach` to prevent Cross-Site Scripting (XSS) attacks.

## 🛠️ Tech Stack

| Category      | Technology                                                                         |
|---------------|------------------------------------------------------------------------------------|
| **Backend**   | Python 3, Flask, Flask-SocketIO, Flask-SQLAlchemy, Flask-Login, Cryptography       |
| **Frontend**  | HTML5, CSS3, Vanilla JavaScript, Socket.IO Client, Font Awesome                    |
| **Database**  | PostgreSQL (Production), SQLite (Development)                                      |
| **Server**    | Gunicorn, Eventlet                                                                 |

## 🚀 Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

*   Python 3.8+
*   Git

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/shadowchat.git
    cd shadowchat
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure environment variables:**
    *   Create a file named `.env` in the project root.
    *   Add the following variables, generating your own unique keys:
    ```ini
    SECRET_KEY='your-generated-secret-key'
    FERNET_KEY='your-generated-fernet-key'
    ```

### Running the Application

The application must be run as a module from its **parent directory**.

1.  **Navigate to the parent directory:**
    ```bash
    # If you are in the 'securechat' folder:
    cd ..
    ```

2.  **Run the app:**
    ```bash
    python -m securechat.app
    ```

3.  Open your browser and go to `http://127.0.0.1:5001`.

## 🚢 Deployment

This application is configured for deployment on platforms like Render. The `gunicorn` start command in the Render service should be:
```bash
gunicorn --worker-class eventlet -w 1 'securechat.app:app'
