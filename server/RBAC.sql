CREATE DATABASE IF NOT EXISTS blogs_app;
CREATE ROLE IF NOT EXISTS "Admin";
GRANT ALL PRIVILEGES ON blogs_app.* TO "Admin";
CREATE USER 'blogy_app'@'%' IDENTIFIED BY '*************';
GRANT 'Admin' TO 'blogy_app'@'%';
SET DEFAULT ROLE 'Admin' TO 'blogy_app'@'%';