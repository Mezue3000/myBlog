CREATE DATABASE IF NOT EXISTS blogs_app;
CREATE ROLE IF NOT EXISTS "Admin";
GRANT ALL PRIVILEGES ON blogs_app.* TO "Admin";
CREATE USER '*********'@'%' IDENTIFIED BY '*************';
GRANT 'Admin' TO '*********'@'%';
SET DEFAULT ROLE 'Admin' TO '*********'@'%';