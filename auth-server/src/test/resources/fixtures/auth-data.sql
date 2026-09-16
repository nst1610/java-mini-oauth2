INSERT INTO roles(role_name) VALUES ('viewer'), ('operator');

INSERT INTO role_scopes(role_id, scope)
SELECT role_id, 'payments:read' FROM roles WHERE role_name IN ('viewer', 'operator');
INSERT INTO role_scopes(role_id, scope)
SELECT role_id, 'payments:write' FROM roles WHERE role_name = 'operator';

INSERT INTO users(user_id, username, password_hash, info, blocked)
VALUES ('u-100', 'alice', '$2a$12$wz.xHv8HOUqeQpVqctMzx.nj.o4art2ctN/BBawcGyqXZu7jrzCGu', '{"display_name":"alice"}', FALSE);
INSERT INTO user_roles(user_id, role_id)
SELECT 'u-100', role_id FROM roles WHERE role_name = 'viewer';

INSERT INTO users(user_id, username, password_hash, info, blocked)
VALUES ('u-200', 'bob', '$2a$12$wz.xHv8HOUqeQpVqctMzx.nj.o4art2ctN/BBawcGyqXZu7jrzCGu', '{"display_name":"bob"}', FALSE);
INSERT INTO user_roles(user_id, role_id)
SELECT 'u-200', role_id FROM roles WHERE role_name = 'operator';

INSERT INTO users(user_id, username, password_hash, info, blocked)
VALUES ('u-300', 'blocked', '$2a$12$wz.xHv8HOUqeQpVqctMzx.nj.o4art2ctN/BBawcGyqXZu7jrzCGu', '{"display_name":"blocked"}', TRUE);
INSERT INTO user_roles(user_id, role_id)
SELECT 'u-300', role_id FROM roles WHERE role_name = 'viewer';

INSERT INTO clients(client_id, client_secret_hash, aud, info)
VALUES ('cli-001', '$2a$12$YRQi4mTQ01dYjsCrbHSh2uQF1Mk26ZgnMux4Sf/1I6DYkwqejMWxK', 'payments-api', '{"name":"Test application"}');
INSERT INTO client_grants(client_id, grant_type) VALUES ('cli-001', 'password');
INSERT INTO client_grants(client_id, grant_type) VALUES ('cli-001', 'refresh_token');
INSERT INTO client_grants(client_id, grant_type) VALUES ('cli-001', 'client_credentials');
INSERT INTO client_scopes(client_id, scope) VALUES ('cli-001', 'payments:read');
INSERT INTO client_scopes(client_id, scope) VALUES ('cli-001', 'payments:write');

INSERT INTO clients(client_id, client_secret_hash, aud, info)
VALUES ('service-001', '$2a$12$YRQi4mTQ01dYjsCrbHSh2uQF1Mk26ZgnMux4Sf/1I6DYkwqejMWxK', 'payments-api', '{"name":"Test application"}');
INSERT INTO client_grants(client_id, grant_type) VALUES ('service-001', 'client_credentials');
INSERT INTO client_scopes(client_id, scope) VALUES ('service-001', 'payments:read');

