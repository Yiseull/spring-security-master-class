INSERT INTO users(username, password, enabled)
VALUES ('user', '{noop}user123', true),
       ('admin01', '{noop}admin123', true),
       ('admin02', '{noop}admin123', true)
;

INSERT INTO authorities(username, authority)
VALUES ('user', 'ROLE_USER'),
       ('admin01', 'ROLE_ADMIN'),
       ('admin02', 'ROLE_ADMIN')
;
