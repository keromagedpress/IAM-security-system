-- =============================================
-- IAM Security System - Complete Database Setup
-- SQL Server 2022
-- =============================================

USE master;
GO

IF EXISTS (SELECT * FROM sys.databases WHERE name = 'iam_security')
BEGIN
    ALTER DATABASE iam_security SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
    DROP DATABASE iam_security;
END
GO

CREATE DATABASE iam_security;
GO

USE iam_security;
GO

-- 1. USERS table
CREATE TABLE users (
    id            UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    username      NVARCHAR(50)  NOT NULL UNIQUE,
    email         NVARCHAR(100) NOT NULL UNIQUE,
    password_hash NVARCHAR(255) NOT NULL,
    is_active     BIT           NOT NULL DEFAULT 1,
    created_at    DATETIME2     NOT NULL DEFAULT GETDATE(),
    last_login    DATETIME2     NULL
);
GO

-- 2. ROLES table
CREATE TABLE roles (
    id          UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    name        NVARCHAR(50)  NOT NULL UNIQUE,
    description NVARCHAR(255) NULL,
    created_at  DATETIME2     NOT NULL DEFAULT GETDATE()
);
GO

-- 3. PERMISSIONS table
CREATE TABLE permissions (
    id          UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    resource    NVARCHAR(100) NOT NULL,
    action      NVARCHAR(50)  NOT NULL,
    description NVARCHAR(255) NULL,
    CONSTRAINT uq_resource_action UNIQUE (resource, action)
);
GO

-- 4. USER_ROLES junction table
CREATE TABLE user_roles (
    id          UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    user_id     UNIQUEIDENTIFIER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UNIQUEIDENTIFIER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at DATETIME2        NOT NULL DEFAULT GETDATE(),
    CONSTRAINT uq_user_role UNIQUE (user_id, role_id)
);
GO

-- 5. ROLE_PERMISSIONS junction table
CREATE TABLE role_permissions (
    id            UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    role_id       UNIQUEIDENTIFIER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UNIQUEIDENTIFIER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    CONSTRAINT uq_role_permission UNIQUE (role_id, permission_id)
);
GO

-- 6. LOGIN_ATTEMPTS table
CREATE TABLE login_attempts (
    id             UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    user_id        UNIQUEIDENTIFIER NULL REFERENCES users(id) ON DELETE SET NULL,
    ip_address     NVARCHAR(45)  NOT NULL,
    success        BIT           NOT NULL DEFAULT 0,
    failure_reason NVARCHAR(255) NULL,
    attempted_at   DATETIME2     NOT NULL DEFAULT GETDATE()
);
GO

-- 7. ACTIVITY_LOGS table
CREATE TABLE activity_logs (
    id         UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    user_id    UNIQUEIDENTIFIER NULL REFERENCES users(id) ON DELETE SET NULL,
    action     NVARCHAR(100)    NOT NULL,
    resource   NVARCHAR(100)    NOT NULL,
    ip_address NVARCHAR(45)     NULL,
    metadata   NVARCHAR(MAX)    NULL,
    created_at DATETIME2        NOT NULL DEFAULT GETDATE()
);
GO

-- 8. ANOMALY_FLAGS table
CREATE TABLE anomaly_flags (
    id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    activity_log_id UNIQUEIDENTIFIER NOT NULL REFERENCES activity_logs(id) ON DELETE CASCADE,
    severity        NVARCHAR(20)     NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    type            NVARCHAR(100)    NOT NULL,
    response_note   NVARCHAR(500)    NULL,
    is_resolved     BIT              NOT NULL DEFAULT 0,
    flagged_at      DATETIME2        NOT NULL DEFAULT GETDATE()
);
GO

-- =============================================
-- INDEXES
-- =============================================
CREATE INDEX ix_login_attempts_user_id  ON login_attempts (user_id);
CREATE INDEX ix_login_attempts_ip       ON login_attempts (ip_address);
CREATE INDEX ix_login_attempts_time     ON login_attempts (attempted_at);
CREATE INDEX ix_activity_logs_user_id   ON activity_logs  (user_id);
CREATE INDEX ix_activity_logs_time      ON activity_logs  (created_at);
CREATE INDEX ix_anomaly_flags_resolved  ON anomaly_flags  (is_resolved);
GO

-- =============================================
-- SEED DATA
-- =============================================
INSERT INTO roles (name, description) VALUES
('admin',   'Full system access'),
('analyst', 'Can view logs and anomalies'),
('viewer',  'Read-only access');
GO

INSERT INTO permissions (resource, action, description) VALUES
('users',     'create',  'Create new users'),
('users',     'read',    'View user details'),
('users',     'update',  'Edit user details'),
('users',     'delete',  'Delete users'),
('logs',      'read',    'View activity logs'),
('anomalies', 'read',    'View anomaly flags'),
('anomalies', 'resolve', 'Mark anomalies as resolved'),
('roles',     'manage',  'Assign and manage roles');
GO

PRINT 'Database iam_security created successfully!';