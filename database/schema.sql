-- SecureSite Audit Database Schema
-- PostgreSQL 15+

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    verification_token_expires TIMESTAMP WITH TIME ZONE,
    reset_password_token VARCHAR(255),
    reset_password_token_expires TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Domains table
CREATE TABLE IF NOT EXISTS domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain_name VARCHAR(255) NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    verification_method VARCHAR(50) DEFAULT 'dns',
    verification_token VARCHAR(255) NOT NULL,
    verification_token_expires TIMESTAMP WITH TIME ZONE,
    verified_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    last_audit_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, domain_name)
);

-- Audits table
CREATE TABLE IF NOT EXISTS audits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    overall_score INTEGER,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit results table
CREATE TABLE IF NOT EXISTS audit_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    check_category VARCHAR(100) NOT NULL,
    check_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    score INTEGER,
    max_score INTEGER,
    details JSONB,
    recommendations JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- HTTPS/TLS results
CREATE TABLE IF NOT EXISTS tls_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    has_https BOOLEAN DEFAULT FALSE,
    tls_version VARCHAR(20),
    cipher_suite VARCHAR(255),
    certificate_valid BOOLEAN DEFAULT FALSE,
    certificate_issuer VARCHAR(500),
    certificate_subject VARCHAR(500),
    certificate_not_before TIMESTAMP WITH TIME ZONE,
    certificate_not_after TIMESTAMP WITH TIME ZONE,
    certificate_days_remaining INTEGER,
    certificate_san TEXT[],
    hsts_enabled BOOLEAN DEFAULT FALSE,
    hsts_max_age INTEGER,
    hsts_include_subdomains BOOLEAN DEFAULT FALSE,
    hsts_preload BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security headers results
CREATE TABLE IF NOT EXISTS header_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    content_security_policy VARCHAR(1000),
    csp_valid BOOLEAN DEFAULT FALSE,
    x_frame_options VARCHAR(100),
    x_content_type_options VARCHAR(100),
    x_xss_protection VARCHAR(100),
    referrer_policy VARCHAR(100),
    permissions_policy VARCHAR(500),
    strict_transport_security VARCHAR(200),
    cross_origin_opener_policy VARCHAR(100),
    cross_origin_resource_policy VARCHAR(100),
    cross_origin_embedder_policy VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Cookie security results
CREATE TABLE IF NOT EXISTS cookie_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    cookie_name VARCHAR(255) NOT NULL,
    has_secure_flag BOOLEAN DEFAULT FALSE,
    has_httponly_flag BOOLEAN DEFAULT FALSE,
    has_samesite_flag BOOLEAN DEFAULT FALSE,
    samesite_value VARCHAR(20),
    path VARCHAR(255),
    domain VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Robots.txt results
CREATE TABLE IF NOT EXISTS robots_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    exists BOOLEAN DEFAULT FALSE,
    content TEXT,
    sitemap_urls TEXT[],
    has_security_txt_reference BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security.txt results
CREATE TABLE IF NOT EXISTS security_txt_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    exists BOOLEAN DEFAULT FALSE,
    content TEXT,
    contact_urls TEXT[],
    expires TIMESTAMP WITH TIME ZONE,
    encryption_urls TEXT[],
    policy_urls TEXT[],
    acknowledged_urls TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Server info results
CREATE TABLE IF NOT EXISTS server_info_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    server_header VARCHAR(255),
    x_powered_by VARCHAR(255),
    technology_stack JSONB,
    ip_address INET,
    country VARCHAR(100),
    isp VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- PDF reports table
CREATE TABLE IF NOT EXISTS pdf_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_path VARCHAR(500) NOT NULL,
    file_size INTEGER,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    download_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);
CREATE INDEX IF NOT EXISTS idx_domains_domain_name ON domains(domain_name);
CREATE INDEX IF NOT EXISTS idx_audits_domain_id ON audits(domain_id);
CREATE INDEX IF NOT EXISTS idx_audits_user_id ON audits(user_id);
CREATE INDEX IF NOT EXISTS idx_audits_status ON audits(status);
CREATE INDEX IF NOT EXISTS idx_audit_results_audit_id ON audit_results(audit_id);
CREATE INDEX IF NOT EXISTS idx_tls_results_audit_id ON tls_results(audit_id);
CREATE INDEX IF NOT EXISTS idx_header_results_audit_id ON header_results(audit_id);
CREATE INDEX IF NOT EXISTS idx_cookie_results_audit_id ON cookie_results(audit_id);
CREATE INDEX IF NOT EXISTS idx_robots_results_audit_id ON robots_results(audit_id);
CREATE INDEX IF NOT EXISTS idx_security_txt_results_audit_id ON security_txt_results(audit_id);
CREATE INDEX IF NOT EXISTS idx_server_info_results_audit_id ON server_info_results(audit_id);
CREATE INDEX IF NOT EXISTS idx_pdf_reports_audit_id ON pdf_reports(audit_id);
CREATE INDEX IF NOT EXISTS idx_pdf_reports_user_id ON pdf_reports(user_id);

-- Trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_domains_updated_at BEFORE UPDATE ON domains
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_audits_updated_at BEFORE UPDATE ON audits
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();