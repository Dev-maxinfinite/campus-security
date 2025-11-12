from flask import Flask, render_template, request, redirect, session, flash, jsonify
import csv
import os
from datetime import datetime
import pandas as pd

app = Flask(__name__)
app.secret_key = 'campus_security_2025'
app.config['SESSION_PERMANENT'] = False

# Initialize CSV files
def init_csv_files():
    # Users CSV
    if not os.path.exists('users.csv'):
        with open('users.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['username', 'password', 'role', 'full_name'])
            writer.writerow(['admin', 'admin123', 'admin', 'System Administrator'])
            writer.writerow(['student1', 'pass123', 'student', 'Rahul Sharma'])
            writer.writerow(['faculty1', 'pass123', 'faculty', 'Dr. Priya Singh'])
    
    # Policies CSV
    if not os.path.exists('policies.csv'):
        with open('policies.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['role', 'time_period', 'allowed_categories', 'blocked_categories'])
            writer.writerow(['student', 'class_time', 'educational,research', 'social,streaming,gaming,torrents'])
            writer.writerow(['student', 'free_time', 'educational,research,limited_social', 'torrents,adult,gaming'])
            writer.writerow(['faculty', 'all_time', 'educational,research,streaming,social', 'malicious,torrents'])
    
    # Access Logs CSV
    if not os.path.exists('access_logs.csv'):
        with open('access_logs.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['timestamp', 'username', 'role', 'action', 'category', 'status'])
    
    # Access Requests CSV
    if not os.path.exists('access_requests.csv'):
        with open('access_requests.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['timestamp', 'username', 'website_url', 'reason', 'urgency', 'status'])

# CSV Helper Functions
def read_csv(filename):
    try:
        with open(filename, 'r') as file:
            return list(csv.DictReader(file))
    except:
        return []

def write_csv(filename, data):
    with open(filename, 'w', newline='') as file:
        if data:
            writer = csv.DictWriter(file, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)

def append_csv(filename, row):
    with open(filename, 'a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=row.keys())
        writer.writerow(row)

# Authentication
def authenticate_user(username, password):
    users = read_csv('users.csv')
    for user in users:
        if user['username'] == username and user['password'] == password:
            return user
    return None

# Policy Engine
def check_access_policy(username, role, website_category):
    current_hour = datetime.now().hour
    time_period = 'class_time' if 8 <= current_hour <= 16 else 'free_time'
    
    policies = read_csv('policies.csv')
    user_policies = [p for p in policies if p['role'] == role and p['time_period'] in [time_period, 'all_time']]
    
    if not user_policies:
        return "ALLOWED", "No specific policy"
    
    for policy in user_policies:
        blocked_categories = policy['blocked_categories'].split(',')
        if website_category in blocked_categories:
            return "BLOCKED", f"Policy violation - {website_category} not allowed during {time_period}"
    
    return "ALLOWED", "Access granted"

# Log Access Attempt
def log_access(username, role, action, category, status):
    log_entry = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'username': username,
        'role': role,
        'action': action,
        'category': category,
        'status': status
    }
    append_csv('access_logs.csv', log_entry)

# Routes
@app.route('/')
def home():
    if 'user' not in session:
        return redirect('/login')
    return redirect('/dashboard')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = authenticate_user(username, password)
        if user:
            session['user'] = user['username']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            log_access(username, user['role'], 'login', 'system', 'SUCCESS')
            return redirect('/dashboard')
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user' in session:
        log_access(session['user'], session['role'], 'logout', 'system', 'SUCCESS')
    session.clear()
    return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    
    policies = read_csv('policies.csv')
    user_policies = [p for p in policies if p['role'] == session['role']]
    
    # Get user stats
    logs = read_csv('access_logs.csv')
    user_logs = [log for log in logs if log['username'] == session['user']]
    total_checks = len([log for log in user_logs if log['action'] == 'access_check'])
    blocked_attempts = len([log for log in user_logs if log['status'] == 'BLOCKED'])
    
    return render_template('dashboard.html', 
                         user=session['user'],
                         role=session['role'],
                         full_name=session['full_name'],
                         policies=user_policies,
                         total_checks=total_checks,
                         blocked_attempts=blocked_attempts)

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/login')
    
    policies = read_csv('policies.csv')
    user_policies = [p for p in policies if p['role'] == session['role']]
    
    # Get user activity stats
    logs = read_csv('access_logs.csv')
    user_logs = [log for log in logs if log['username'] == session['user']]
    total_logins = len([log for log in user_logs if log['action'] == 'login'])
    policy_checks = len([log for log in user_logs if log['action'] == 'access_check'])
    blocked_count = len([log for log in user_logs if log['status'] == 'BLOCKED'])
    
    # Get last login time
    login_logs = [log for log in user_logs if log['action'] == 'login']
    last_login = login_logs[-1]['timestamp'] if login_logs else 'Never'
    
    return render_template('profile.html',
                         user=session['user'],
                         role=session['role'], 
                         full_name=session['full_name'],
                         policies=user_policies,
                         total_logins=total_logins,
                         policy_checks=policy_checks,
                         blocked_count=blocked_count,
                         last_login=last_login)

@app.route('/request_access', methods=['GET', 'POST'])
def request_access():
    if 'user' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        website_url = request.form['website_url']
        reason = request.form['reason']
        urgency = request.form['urgency']
        
        # Save request to CSV
        request_data = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'username': session['user'],
            'website_url': website_url,
            'reason': reason,
            'urgency': urgency,
            'status': 'pending'
        }
        
        append_csv('access_requests.csv', request_data)
        flash('Access request submitted successfully!', 'success')
        return redirect('/dashboard')
    
    return render_template('request_access.html', 
                         user=session['user'], 
                         full_name=session['full_name'])

@app.route('/my_requests')
def my_requests():
    if 'user' not in session:
        return redirect('/login')
    
    requests = read_csv('access_requests.csv')
    user_requests = [req for req in requests if req['username'] == session['user']]
    
    return render_template('my_requests.html',
                         user=session['user'],
                         full_name=session['full_name'],
                         requests=user_requests)

@app.route('/check_access')
def check_access():
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'})
    
    website_category = request.args.get('category', 'educational')
    status, message = check_access_policy(session['user'], session['role'], website_category)
    
    # Log the access attempt
    log_access(session['user'], session['role'], 'access_check', website_category, status)
    
    return jsonify({
        'user': session['user'],
        'role': session['role'],
        'category': website_category,
        'status': status,
        'message': message,
        'time': datetime.now().strftime("%H:%M")
    })

@app.route('/admin')
def admin():
    if 'user' not in session or session['role'] != 'admin':
        return redirect('/dashboard')
    
    # Get statistics
    logs = read_csv('access_logs.csv')
    users = read_csv('users.csv')
    policies = read_csv('policies.csv')
    requests = read_csv('access_requests.csv')
    
    # Basic analytics
    total_logs = len(logs)
    blocked_attempts = len([log for log in logs if log['status'] == 'BLOCKED'])
    total_users = len(users)
    pending_requests = len([req for req in requests if req['status'] == 'pending'])
    
    return render_template('admin.html',
                         user=session['user'],
                         role=session['role'],
                         full_name=session['full_name'],
                         total_logs=total_logs,
                         blocked_attempts=blocked_attempts,
                         total_users=total_users,
                         pending_requests=pending_requests,
                         logs=logs[-10:])  # Last 10 logs

@app.route('/admin/requests')
def admin_requests():
    if 'user' not in session or session['role'] != 'admin':
        return redirect('/dashboard')
    
    requests = read_csv('access_requests.csv')
    
    return render_template('admin_requests.html',
                         user=session['user'],
                         full_name=session['full_name'],
                         requests=requests)

@app.route('/manage_requests')
def manage_requests():
    if 'user' not in session or session['role'] != 'admin':
        return redirect('/dashboard')
    
    requests = read_csv('access_requests.csv')
    
    return render_template('manage_requests.html',
                         user=session['user'],
                         full_name=session['full_name'],
                         requests=requests)

@app.route('/update_request_status', methods=['POST'])
def update_request_status():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'})
    
    request_id = int(request.form['request_id'])
    new_status = request.form['status']
    
    requests = read_csv('access_requests.csv')
    if 0 <= request_id < len(requests):
        requests[request_id]['status'] = new_status
        write_csv('access_requests.csv', requests)
        
        log_access(session['user'], session['role'], 'update_request', f'status_{new_status}', 'SUCCESS')
        return jsonify({'success': True, 'message': f'Request {new_status}'})
    
    return jsonify({'error': 'Request not found'})

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'user' not in session or session['role'] != 'admin':
        return jsonify({'error': 'Unauthorized'})
    
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    full_name = request.form['full_name']
    
    users = read_csv('users.csv')
    
    # Check if user exists
    if any(user['username'] == username for user in users):
        return jsonify({'error': 'User already exists'})
    
    # Add new user
    new_user = {
        'username': username,
        'password': password,
        'role': role,
        'full_name': full_name
    }
    append_csv('users.csv', new_user)
    log_access(session['user'], session['role'], 'add_user', f'user_{username}', 'SUCCESS')
    
    return jsonify({'success': True, 'message': 'User added successfully'})

if __name__ == '__main__':
    init_csv_files()
    app.run(debug=True)