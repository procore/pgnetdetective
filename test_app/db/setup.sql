CREATE DATABASE apple_picker_extreme;
CREATE ROLE pgnet WITH PASSWORD 'pgnet';
ALTER ROLE pgnet LOGIN;
GRANT ALL PRIVILEGES ON DATABASE apple_picker_extreme TO pgnet;
ALTER DATABASE apple_picker_extreme OWNER TO pgnet;
