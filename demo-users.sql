-- Demo Users for A2Z SOC Platform
-- These credentials will be displayed on the login page for demonstration

-- First, let's create or get the demo organization
DO $$
DECLARE
    demo_org_id UUID;
BEGIN
    -- Try to get existing demo organization or create a new one
    SELECT id INTO demo_org_id FROM organizations WHERE domain = 'demo.a2zsoc.com';
    
    IF demo_org_id IS NULL THEN
        demo_org_id := '123e4567-e89b-12d3-a456-426614174000';
        INSERT INTO organizations (id, name, domain, subscription_tier, subscription_status) 
        VALUES (
            demo_org_id,
            'A2Z Demo Organization', 
            'demo.a2zsoc.com',
            'enterprise',
            'active'
        );
    END IF;

    -- Delete existing demo users to avoid conflicts
    DELETE FROM users WHERE email IN ('admin@demo.com', 'analyst@demo.com', 'manager@demo.com', 'viewer@demo.com');

    -- Demo Admin User
    INSERT INTO users (
        id, 
        organization_id, 
        email, 
        password_hash, 
        first_name, 
        last_name, 
        role, 
        is_active, 
        email_verified
    ) VALUES (
        '123e4567-e89b-12d3-a456-426614174001',
        demo_org_id,
        'admin@demo.com',
        '$2b$10$rOFQm8XvjDv7YNdKOqWi5ONwP5f7vKNiOzJlqrDGKfkV2YqTQvKrK', -- password: demo123
        'Demo',
        'Admin',
        'admin',
        true,
        true
    );

    -- Demo Analyst User  
    INSERT INTO users (
        id,
        organization_id,
        email,
        password_hash,
        first_name,
        last_name, 
        role,
        is_active,
        email_verified
    ) VALUES (
        '123e4567-e89b-12d3-a456-426614174002',
        demo_org_id,
        'analyst@demo.com',
        '$2b$10$rOFQm8XvjDv7YNdKOqWi5ONwP5f7vKNiOzJlqrDGKfkV2YqTQvKrK', -- password: demo123
        'Demo',
        'Analyst',
        'analyst',
        true,
        true
    );

    -- Demo Viewer User
    INSERT INTO users (
        id,
        organization_id,
        email,
        password_hash,
        first_name,
        last_name,
        role,
        is_active,
        email_verified
    ) VALUES (
        '123e4567-e89b-12d3-a456-426614174003',
        demo_org_id,
        'viewer@demo.com',
        '$2b$10$rOFQm8XvjDv7YNdKOqWi5ONwP5f7vKNiOzJlqrDGKfkV2YqTQvKrK', -- password: demo123
        'Demo',
        'Viewer',
        'viewer',
        true,
        true
    );

    -- Demo SOC Manager
    INSERT INTO users (
        id,
        organization_id,
        email,
        password_hash,
        first_name,
        last_name,
        role,
        is_active,
        email_verified
    ) VALUES (
        '123e4567-e89b-12d3-a456-426614174004',
        demo_org_id,
        'manager@demo.com',
        '$2b$10$rOFQm8XvjDv7YNdKOqWi5ONwP5f7vKNiOzJlqrDGKfkV2YqTQvKrK', -- password: demo123
        'SOC',
        'Manager',
        'admin',
        true,
        true
    );

    RAISE NOTICE 'Demo users created successfully for organization %', demo_org_id;
END $$; 