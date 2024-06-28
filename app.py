from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import sqlite3
import re
import pyotp
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
import io
import random
import string
import time
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib.units import inch
from datetime import datetime
app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'students.db'
CERTIFICATES_DIR = 'certificates/'

# Initialize the database
def init_db():
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
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
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                password TEXT,
                role TEXT,
                otp_secret TEXT
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"SQLite error in init_db(): {e}")
    finally:
        if conn:
            conn.close()
@app.route('/index')
def index():
    # Render the index.html template
    return render_template('index.html')


@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']
    otp = request.form.get('otp')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ? AND role = ?', (email, role))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        if user[4]:  # Check if OTP secret exists
            totp = pyotp.TOTP(user[4])
            if not otp or not totp.verify(otp):
                flash('Invalid OTP code.')
                return render_template('login.html')
        session['user'] = user
        if role == 'student':
            return redirect(url_for('index'))
        elif role == 'faculty':
            return redirect(url_for('students'))
        elif role == 'admin':
            return redirect(url_for('admin_panel'))
    else:
        flash('Invalid login credentials.')
        return redirect(url_for('login'))
    return redirect(url_for('login'))  # Default redirect to login page
# @app.route('/register')
# def register():
#     return render_template('register.html')

@app.route('/register', methods=['GET', 'POST'])
def register_post():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        otp_secret = pyotp.random_base32()

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (email, password, role, otp_secret) VALUES (?, ?, ?, ?)',
                           (email, hashed_password, role, otp_secret))
            conn.commit()

            totp = pyotp.TOTP(otp_secret)
            qr_code_url = totp.provisioning_uri(name=email, issuer_name="Bonafide Certificate Generator")

            flash('Registration successful! Please scan the QR code with your authenticator app.')
            return render_template('register.html', qr_code_url=qr_code_url)
        except sqlite3.Error as e:
            flash(f"Error registering user: {e}")
            conn.rollback()
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/submit_student_details', methods=['POST'])
def submit_student_details():
    if request.method == 'POST':
        name = request.form['name']
        father_name = request.form['father_name']
        mother_name = request.form['mother_name']
        registration_number = request.form['registration_number']
        phone_number = request.form['phone_number']
        year = request.form['year']
        current_cgpa = request.form['current_cgpa']
        university_name = request.form['university_name']
        email = request.form['email']
        course_name = request.form['course_name']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO students (name, father_name, mother_name, registration_number,
                                      phone_number, year, current_cgpa, university_name,
                                      email, course_name)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (name, father_name, mother_name, registration_number,
                  phone_number, year, current_cgpa, university_name,
                  email, course_name))
            conn.commit()
            flash('Student details submitted successfully!')
        except sqlite3.Error as e:
            flash(f"Error submitting student details: {e}")
            conn.rollback()
        finally:
            conn.close()

        return redirect(url_for('index'))  # Redirect to the index page after successful submission

    return redirect(url_for('index'))  # Default redirect to the index page if not a POST request

@app.route('/admin_panel')
def admin_panel():
    if 'user' not in session or session['user'][3] != 'admin':
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE role = ?', ('student',))
    students = cursor.fetchall()
    cursor.execute('SELECT * FROM users WHERE role = ?', ('faculty',))
    faculties = cursor.fetchall()
    conn.close()

    return render_template('admin_panel.html', students=students, faculties=faculties)

@app.route('/delete_account/<int:user_id>', methods=['POST'])
def delete_account(user_id):
    if 'user' not in session or session['user'][3] != 'admin':
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('Account deleted successfully.')
    return redirect(url_for('admin_panel'))

@app.route('/students')
def students():
    if 'user' not in session or session['user'][3] != 'faculty':
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM students')
    students = cursor.fetchall()
    conn.close()
    return render_template('students.html', students=students)

@app.route('/approve/<int:student_id>', methods=['POST'])
def approve(student_id):
    if 'user' not in session or session['user'][3] != 'faculty':
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM students WHERE id = ?', (student_id,))
    student = cursor.fetchone()
    conn.close()

    if student:
        # Generate the bonafide certificate
        generate_certificate(student)

        # Send the certificate via email
        send_email(student[9], f"{student[1]}_bonafide_certificate.pdf")

        flash('Certificate generated and sent to the student.')
    else:
        flash('Student not found.')

    return redirect(url_for('students'))
@app.route('/decline/<int:student_id>', methods=['POST'])
def decline(student_id):
    if 'user' not in session or session['user'][3] != 'faculty':
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM students WHERE id = ?', (student_id,))
    student = cursor.fetchone()

    if not student:
        flash('Student not found.')
        return redirect(url_for('students'))

    try:
        # Delete student from database
        cursor.execute('DELETE FROM students WHERE id = ?', (student_id,))
        conn.commit()

        # Send email to student's email for review
        send_review_email(student[9], request.form.get('message'))

        flash('Student declined successfully and email sent for review.')
    except Exception as e:
        flash(f'Error declining student: {e}')
        conn.rollback()
    finally:
        conn.close()

    return redirect(url_for('students'))


def send_review_email(recipient_email, message=None):
    sender_email = "auth.me.official@outlook.com"   # Update with your sender email
    smtp_server = "smtp-mail.outlook.com"  # Update with your SMTP server
    smtp_port = 587  # Update with your SMTP port
    subject = "Review Required: Your Application for Bonafide Certificate"
    email_password = "#aB@8098"
    body = f"Dear Student,\n\n" \
           f"We regret to inform you that your application requires further review.\n\n"
    if message:
        body += f"Reason: {message}\n\n"
    body += "Please review your application details and contact us for further assistance.\n\n" \
            "Best regards,\nUniversity Administration"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            # Add your SMTP login credentials here if required
            server.login(sender_email, email_password)
            text = msg.as_string()
            server.sendmail(sender_email, recipient_email, text)
            print("Review email sent successfully!")
    except Exception as e:
        print(f"Failed to send review email. Error: {str(e)}")

@app.route('/search_certificate', methods=['GET', 'POST'])
def search_certificate():
    if request.method == 'POST':
        obfuscated_string = request.form['obfuscated_string']
        certificate_path = f"{CERTIFICATES_DIR}{obfuscated_string}.pdf"
        try:
            return send_file(certificate_path, as_attachment=True)
        except FileNotFoundError:
            flash('Certificate not found.')
            return render_template('search_certificate.html')
    return render_template('search_certificate.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

def generate_certificate(student):
    name, father_name, registration_number, current_cgpa, year, university_name, course_name = (
        student[1], student[2], student[4], student[7], student[6], student[8], student[10]
    )
    obfuscated_string = obfuscate_string(registration_number)
    width, height = letter
    packet = io.BytesIO()
    can = canvas.Canvas(packet, pagesize=letter)
    background = ImageReader(r"C:\Users\nikun\OneDrive\Desktop\Project QR Code - Copy\Bonafide_Certificate_Template.png")
    can.drawImage(background, 0, 0, width=8.5*72, height=11*72)

    # text = f"This is to certify that Mr./Ms. {name}, S/O or D/O of Mr./Ms. {father_name}\n" \
    #        f"bearing roll number {registration_number}, is a student of {course_name}.\n" \
    #        f"He/She has a current CGPA of {current_cgpa} for the academic year {year}.\n" \
    #        f"He/She is a bonafide student of {university_name}.\n\n" \
    #        f"Character description\n" \
    #        f"He/She is reliable, sincere, hardworking, and bears a good moral character."


    # Get the current date
    current_date = datetime.now().strftime('%d/%m/%Y')
        # Add date
    can.setFont("Times-Italic", 12)  # Change the font style and size for the date
    can.drawString(width - 1.6 * inch, height - 2 * inch, f"Date: {current_date}")
    # Add body of the certificate
    can.setFont("Times-Roman", 12)  # Change the font style and size for the body text
    can.drawString(1 * inch, height - 3.2 * inch, f"This is to certify that Mr./Ms. {name}, S/O or D/O of Mr./Ms. {father_name}")
    can.drawString(1 * inch, height - 3.6 * inch, f"bearing roll number {registration_number}, is a student of {course_name}.")
    can.drawString(1 * inch, height - 4.0 * inch, f"He/She has a current CGPA of {current_cgpa} for the academic year {year}.")
    can.drawString(1 * inch, height - 4.4 * inch, f"He/She is a bonafide student of {university_name}.")
    # Add character description
    can.drawString(1 * inch, height - 6.2 * inch, "He/She is reliable, sincere, hardworking, and bears a good moral character.")
    # can.drawString(100, 500, text)
    # Add signature and university name
    can.drawString(1 * inch, height - 8.0 * inch, "Signature: Registrar/Principal/Dean")
    can.drawString(width - 3 * inch, height - 8.0 * inch, university_name)
    # Generate QR code
    qr = qrcode.QRCode()
    qr.add_data(obfuscated_string)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    can.drawImage(ImageReader(io.BytesIO(img_byte_arr)), 500, 100, 100, 100)

    can.save()

    packet.seek(0)
    with open(f"{CERTIFICATES_DIR}{obfuscated_string}.pdf", 'wb') as f:
        f.write(packet.getbuffer())

def obfuscate_string(registration_number):
    timestamp = int(time.time())
    random_number = random.randint(1000, 9999)
    obfuscated_string = f"{registration_number}-{random_number}-{timestamp}"
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))

def send_email(recipient, filename):
    sender_email = "auth.me.official@outlook.com"
    sender_password = "#aB@8098"
    smtp_server = "smtp-mail.outlook.com"
    smtp_port = 587

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = "Your Bonafide Certificate"

    body = "Please find attached your Bonafide Certificate.\n\nBest regards,\nUniversity Administration"

    msg.attach(MIMEText(body, 'plain'))

    filename = f"{CERTIFICATES_DIR}{filename}"
    attachment = open(filename, "rb")

    p = MIMEBase('application', 'octet-stream')
    p.set_payload(attachment.read())

    encoders.encode_base64(p)
    p.add_header('Content-Disposition', f'attachment; filename= {filename}')
    msg.attach(p)

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, recipient, text)
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email. Error: {str(e)}")

    attachment.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

