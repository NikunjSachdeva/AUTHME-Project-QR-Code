-- schema.sql

CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    father_name TEXT,
    mother_name TEXT,
    registration_number TEXT,
    phone_number TEXT,
    year TEXT,
    current_cgpa TEXT,
    university_name TEXT,
    email TEXT,
    course_name TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    password TEXT,
    role TEXT,
    otp_secret TEXT
);
