# Golang Authentication & Role Management System

## 📋 Overview

A comprehensive authentication and role-based access control system built with Go, inspired by Discord's permission model. This system provides hierarchical role management, granular permissions, and secure JWT-based authentication.

## 🏗️ Architecture

```
backendv2/
├── cmd/
│   └── server/
│       └── main.go              # Application entry point
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── internal/
│   ├── config/
│   │   └── config.go            # Configuration management
│   ├── handlers/
│   │   ├── auth.go              # Authentication handlers
│   │   ├── users.go             # User management handlers
│   │   └── roles.go             # Role management handlers
│   ├── middleware/
│   │   ├── auth.go              # JWT authentication middleware
│   │   ├── rbac.go              # Role-based access control
│   │   └── cors.go              # CORS middleware
│   ├── models/
│   │   ├── user.go              # User data models
│   │   ├── role.go              # Role data models
│   │   └── permission.go        # Permission data models
│   ├── repository/
│   │   ├── users/
│   │   │   └── user_repo.go     # User data access layer
│   │   ├── roles/
│   │   │   └── role_repo.go     # Role data access layer
│   │   └── auth/
│   │       └── session_repo.go  # Session management
│   ├── services/
│   │   ├── auth.go              # Authentication business logic
│   │   ├── user.go              # User management service
│   │   └── rbac.go              # Role-based access control service
│   └── utils/
│       ├── jwt.go               # JWT utilities
│       ├── hash.go              # Password hashing
│       └── validator.go         # Input validation
├── pkg/
│   └── types/
│       ├── requests.go          # API request types
│       ├── responses.go         # API response types
│       └── errors.go            # Custom error types
├── schema/
│   ├── migrations/
│   │   ├── 001_create_users.sql
│   │   ├── 002_create_roles.sql
│   │   ├── 003_create_permissions.sql
│   │   └── 004_create_user_roles.sql
│   └── seeds/
│       └── default_roles.sql
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## 🚀 Getting Started

### Prerequisites

- Go 1.24+
- PostgreSQL 15+
- Redis 6+ (optional, for session management)
- Docker & Docker Compose

### Installation

1. **Clone the repository**
```bash
git clone <repository-url>
cd backendv2
```

2. **Install dependencies**
```bash
go mod download
```

3. **Set up environment variables**
```bash
cp .env.example .env
```

Edit `.env` file:
```env
# Server Configuration
SERVER_HOST=localhost
SERVER_PORT=8080
ENVIRONMENT=development

# Database Configuration
DB_DRIVER=postgres
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=postgres
DB_DATABASE=auth_system

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRED=24h
JWT_REFRESH_EXPIRED=168h

# Redis Configuration (optional)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
```

4. **Run database migrations**
```bash
make migrate-up
```

5. **Seed default roles**
```bash
make seed
```

6. **Start the application**
```bash
make run
```

## 🔐 Authentication System

### JWT Token Structure

```json
{
  "user_id": "uuid",
  "username": "john_doe",
  "roles": ["admin", "moderator"],
  "permissions": ["read_messages", "write_messages", "manage_users"],
  "exp": 1699123456,
  "iat": 1699037056
}
```

### Authentication Flow

1. **Registration/Login** → Generate JWT token
2. **Request with token** → Middleware validates JWT
3. **Extract user roles** → Check permissions
4. **Grant/Deny access** → Based on required permissions

## 👥 Role Management System

### Role Hierarchy (Discord-inspired)

```
Owner
├── Admin
│   ├── Moderator
│   │   ├── Member
│   │   └── Guest
│   └── Bot
└── Banned
```

### Permission System

#### User Permissions
- `read_profile`
- `edit_profile`
- `delete_account`

#### Content Permissions
- `read_messages`
- `write_messages`
- `edit_messages`
- `delete_messages`
- `pin_messages`

#### Moderation Permissions
- `kick_members`
- `ban_members`
- `mute_members`
- `manage_roles`
- `manage_channels`

#### Administration Permissions
- `manage_server`
- `manage_users`
- `view_audit_logs`
- `manage_integrations`

### Role Configuration Example

```json
{
  "name": "Moderator",
  "color": "#3498db",
  "position": 3,
  "permissions": [
    "read_messages",
    "write_messages",
    "delete_messages",
    "kick_members",
    "mute_members"
  ],
  "mentionable": true,
  "hoist": true
}
```

## 📡 API Endpoints

### Authentication
```http
POST   /api/v1/auth/register     # User registration
POST   /api/v1/auth/login        # User login
POST   /api/v1/auth/refresh      # Refresh token
POST   /api/v1/auth/logout       # Logout
GET    /api/v1/auth/me           # Get current user
```

### User Management
```http
GET    /api/v1/users             # List users (admin only)
GET    /api/v1/users/:id         # Get user by ID
PUT    /api/v1/users/:id         # Update user
DELETE /api/v1/users/:id         # Delete user (admin only)
POST   /api/v1/users/:id/roles   # Assign role to user
DELETE /api/v1/users/:id/roles/:role_id  # Remove role from user
```

### Role Management
```http
GET    /api/v1/roles             # List all roles
POST   /api/v1/roles             # Create new role (admin only)
GET    /api/v1/roles/:id         # Get role by ID
PUT    /api/v1/roles/:id         # Update role (admin only)
DELETE /api/v1/roles/:id         # Delete role (admin only)
GET    /api/v1/roles/:id/permissions  # Get role permissions
PUT    /api/v1/roles/:id/permissions  # Update role permissions
```

### Permission Check
```http
GET    /api/v1/permissions/check?permission=manage_users  # Check if user has permission
GET    /api/v1/permissions/user/:id                      # Get user's all permissions
```

## 🔧 Usage Examples

### Register a new user
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "John Doe",
    "username": "johndoe",
    "email": "john@example.com",
    "password": "SecurePassword123!"
  }'
```

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePassword123!"
  }'
```

### Access protected endpoint
```bash
curl -X GET http://localhost:8080/api/v1/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Create a new role
```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Custom Role",
    "color": "#ff5733",
    "permissions": ["read_messages", "write_messages"],
    "position": 2
  }'
```

### Assign role to user
```bash
curl -X POST http://localhost:8080/api/v1/users/123/roles \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "456"
  }'
```

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name VARCHAR(255) NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    avatar_url VARCHAR(500),
    status VARCHAR(20) DEFAULT 'active',
    email_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Roles Table
```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    color VARCHAR(7) DEFAULT '#99aab5',
    position INTEGER DEFAULT 0,
    mentionable BOOLEAN DEFAULT true,
    hoist BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Permissions Table
```sql
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### User Roles Junction Table
```sql
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)