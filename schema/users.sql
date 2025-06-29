-- Tabel Users
CREATE TABLE users (
    id VARCHAR(200) PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    phone VARCHAR(20),
    is_active BOOLEAN DEFAULT true,
    email_verified_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabel Roles
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL, -- admin, member, reseller, platinum
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabel Permissions
CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL, -- edit_price, view_orders, manage_users, etc
    description TEXT,
    resource VARCHAR(50), -- products, orders, users, etc
    action VARCHAR(50), -- create, read, update, delete, manage
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabel Role Permissions (Many-to-Many)
CREATE TABLE role_permissions (
    id SERIAL PRIMARY KEY,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id)
);

-- Tabel User Roles (Many-to-Many, user bisa punya multiple roles)
CREATE TABLE user_roles (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(200) REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by VARCHAR(200) REFERENCES users(id), -- siapa yang assign role ini
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL, -- role bisa expired (optional)
    is_active BOOLEAN DEFAULT true,
    UNIQUE(user_id, role_id)
);

-- Tabel Sessions
CREATE TABLE sessions (
    id VARCHAR(200) PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(200) REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    device_info TEXT,
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabel Verification Tokens (untuk email verification, password reset, etc)
CREATE TABLE verification_tokens (
    id VARCHAR(200) PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(200) REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    token_type VARCHAR(50) NOT NULL, -- email_verification, password_reset, etc
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_token_hash (token_hash),
    INDEX idx_user_token_type (user_id, token_type)
);

-- Tabel Products (contoh untuk edit price)
CREATE TABLE products (
    id VARCHAR(200) PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    base_price DECIMAL(12,2) NOT NULL,
    stock INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_by VARCHAR(200) REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tabel Product Prices (untuk tracking perubahan harga)
CREATE TABLE product_prices (
    id SERIAL PRIMARY KEY,
    product_id VARCHAR(200) REFERENCES products(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id), -- harga khusus per role
    price DECIMAL(12,2) NOT NULL,
    discount_percentage DECIMAL(5,2) DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_by VARCHAR(200) REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(product_id, role_id)
);

-- Tabel Orders (contoh relasi dengan user dan role)
CREATE TABLE orders (
    id VARCHAR(200) PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(200) REFERENCES users(id),
    user_role_id INTEGER REFERENCES roles(id), -- role saat order dibuat
    total_amount DECIMAL(12,2) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default roles
INSERT INTO roles (name, description) VALUES 
    ('admin', 'Full system access'),
    ('member', 'Basic member access'),
    ('reseller', 'Can edit prices and manage products'),
    ('platinum', 'Premium member with special pricing');

-- Insert default permissions
INSERT INTO permissions (name, description, resource, action) VALUES 
    ('manage_users', 'Can create, edit, delete users', 'users', 'manage'),
    ('view_users', 'Can view user list', 'users', 'read'),
    ('edit_prices', 'Can edit product prices', 'products', 'edit_price'),
    ('view_products', 'Can view products', 'products', 'read'),
    ('manage_products', 'Can create, edit, delete products', 'products', 'manage'),
    ('view_orders', 'Can view orders', 'orders', 'read'),
    ('manage_orders', 'Can manage order status', 'orders', 'manage'),
    ('view_reports', 'Can view system reports', 'reports', 'read');

-- Assign permissions to roles
INSERT INTO role_permissions (role_id, permission_id) VALUES 
    -- Admin permissions (semua akses)
    (1, 1), (1, 2), (1, 3), (1, 4), (1, 5), (1, 6), (1, 7), (1, 8),
    -- Member permissions (basic)
    (2, 4), (2, 6),
    -- Reseller permissions (bisa edit harga)
    (3, 3), (3, 4), (3, 6), (3, 7),
    -- Platinum permissions (view + special pricing)
    (4, 4), (4, 6);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_product_prices_product_role ON product_prices(product_id, role_id);
CREATE INDEX idx_orders_user_id ON orders(user_id);
CREATE INDEX idx_orders_status ON orders(status);