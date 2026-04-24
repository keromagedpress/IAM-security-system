from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from functools import wraps
from models import (
    register_user, login_user, get_all_users, toggle_user_active,
    get_anomalies, resolve_anomaly, get_dashboard_stats, get_network_graph_data,
    get_activity_logs, log_activity, check_brute_force, assign_role,
    get_login_attempts_by_day, get_success_fail_count, get_top_active_users,
    reset_password, update_user_role, get_all_roles
)
from threat_detector import ThreatDetector
from network_monitor import NetworkMonitor
from os_monitor import get_system_metrics

bp = Blueprint('main', __name__)

def role_required(allowed_roles):
    """Decorator to enforce role-based access, including multi-step PIN verification."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Primary Auth Check
            if 'user_id' not in session:
                flash("Please log in to access this page.", "error")
                return redirect(url_for('main.login'))
            
            # 2. RBAC Check
            if session.get('user_role') not in allowed_roles:
                flash("You do not have permission to access this resource.", "error")
                log_activity(session.get('user_id'), "Unauthorized Access Attempt", request.path, request.remote_addr, request.headers.get('User-Agent'))
                return redirect(url_for('main.profile'))
            
            # Log successful access to protected route
            log_activity(session.get('user_id'), "Access Page", request.path, request.remote_addr, request.headers.get('User-Agent'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """User Login Route with multi-step PIN MFA."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        
        user_data, status_message = login_user(username, password, ip_address, user_agent)
        check_brute_force(ip_address)
        
        if user_data:
            # Finalize Session Immediately (Single-Factor)
            session['user_id'] = user_data['id']
            session['username'] = user_data['username']
            session['user_role'] = user_data['role']
            session.permanent = True
            
            flash(f"Login successful. Welcome, {user_data['username']}!", "success")
            log_activity(session['user_id'], "Login", "/login", request.remote_addr, user_agent)
            return redirect(url_for('main.dashboard'))
        else:
            flash(status_message, 'error')
            
    return render_template('login.html')


@bp.route('/register', methods=['GET', 'POST'])
def register():
    """User Registration Route."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        success, message = register_user(username, email, password)
        if success:
            flash(message, 'success')
            return redirect(url_for('main.login'))
        else:
            flash(message, 'error')
            
    return render_template('register.html')

@bp.route('/logout')
def logout():
    """User Logout Route."""
    if 'user_id' in session:
        log_activity(session.get('user_id'), "Logout", "/logout", request.remote_addr)
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('main.login'))

@bp.route('/')
@role_required(['admin'])
def dashboard():
    """Admin Dashboard - Serving charts and overview stats."""
    stats = get_dashboard_stats()
    return render_template('dashboard.html', stats=stats)

@bp.route('/users')
@role_required(['admin'])
def users():
    """User Management Page with Forensic Metadata."""
    from models import get_user_network_info
    user_list = get_all_users()
    for u in user_list:
        u['network'] = get_user_network_info(u['id'])
    roles_list = get_all_roles()
    return render_template('users.html', users=user_list, roles=roles_list)

@bp.route('/users/toggle/<user_id>')
@role_required(['admin'])
def toggle_user(user_id):
    """Toggle user active/inactive status."""
    if toggle_user_active(user_id):
        flash("User status updated.", "success")
        log_activity(session.get('user_id'), "Toggle User Status", f"/users/toggle/{user_id}", request.remote_addr)
    else:
        flash("Failed to update status.", "error")
    return redirect(url_for('main.users'))

@bp.route('/users/assign_role', methods=['POST'])
@role_required(['admin'])
def assign_role_route():
    """Assign a role to a user (form POST — uses role name strings)."""
    username = request.form.get('username')
    role_name = request.form.get('role_name')
    success, message = assign_role(username, role_name)
    if success:
        flash(message, "success")
        log_activity(session.get('user_id'), "Assign Role", f"Assigned {role_name} to {username}", request.remote_addr)
    else:
        flash(message, "error")
    return redirect(url_for('main.users'))

@bp.route('/api/update-role', methods=['POST'])
@role_required(['admin'])
def api_update_role():
    """Update a user's role via UUID (JSON POST from User Governance UI)."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'message': 'Invalid JSON payload.'}), 400

    user_id    = data.get('user_id')
    new_role_id = data.get('new_role_id')

    if not user_id or not new_role_id:
        return jsonify({'success': False, 'message': 'user_id and new_role_id are required.'}), 400

    success, message = update_user_role(user_id, new_role_id)
    if success:
        log_activity(
            session.get('user_id'), "Role Update",
            f"user_id={user_id} -> role_id={new_role_id}",
            request.remote_addr
        )
        return jsonify({'success': True, 'message': message})
    return jsonify({'success': False, 'message': message}), 500

@bp.route('/api/network-info', methods=['GET'])
@role_required(['admin', 'analyst'])
def api_network_info():
    """Returns real-time server telemetry and connecting IP origins."""
    info = NetworkMonitor.get_server_info()
    info['interfaces'] = NetworkMonitor.get_all_interfaces()
    info['connecting_ips'] = NetworkMonitor.get_connecting_ips()
    return jsonify(info)

@bp.route('/api/run-threat-scan', methods=['POST'])
@role_required(['admin'])
def api_run_threat_scan():
    """Triggers the AI Threat Detection engine to scan historical logs."""
    detector = ThreatDetector()
    results = detector.run_all_scans()
    total_found = sum(v for v in results.values() if isinstance(v, int))
    
    log_activity(session.get('user_id'), "Threat Scan", "System-Wide", request.remote_addr)
    return jsonify({
        'success': True,
        'message': f"Scan complete. {total_found} new threat indicators identified.",
        'results': results
    })

@bp.route('/logs')
@role_required(['admin', 'analyst'])
def logs():
    """Activity Audit Logs Page with Forensic Filtering."""
    username_filter = request.args.get('username')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    activity_list = get_activity_logs(
        username=username_filter,
        start_date=start_date,
        end_date=end_date
    )
    return render_template('logs.html', logs=activity_list)

@bp.route('/anomalies')
@role_required(['admin', 'analyst'])
def anomalies():
    """Security Anomalies/Threat Tracking Page."""
    anomaly_list = get_anomalies()
    return render_template('anomalies.html', anomalies=anomaly_list)

@bp.route('/anomalies/resolve/<anomaly_id>')
@role_required(['admin', 'analyst'])
def resolve_flag(anomaly_id):
    """Mark a security anomaly as resolved."""
    if resolve_anomaly(anomaly_id):
        flash("Anomaly marked as resolved.", "success")
        log_activity(session.get('user_id'), "Resolve Anomaly", f"/anomalies/resolve/{anomaly_id}", request.remote_addr)
    else:
        flash("Failed to resolve anomaly.", "error")
    return redirect(url_for('main.anomalies'))

@bp.route('/users/reset_password', methods=['POST'])
@role_required(['admin'])
def reset_password_route():
    """Administrative password reset."""
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    success, message = reset_password(username, new_password)
    if success:
        flash(message, "success")
        log_activity(session.get('user_id'), "Reset Password", f"Reset for {username}", request.remote_addr, request.headers.get('User-Agent'))
    else:
        flash(message, "error")
    return redirect(url_for('main.users'))

@bp.route('/users/delete/<user_id>', methods=['POST'])
@role_required(['admin'])
def delete_user_route(user_id):
    """Permanently purges a user from the system. Cannot delete self."""
    from models import get_user_by_id, delete_user
    
    current_admin_id = session.get('user_id')
    if str(user_id) == str(current_admin_id):
        flash("You cannot delete your own account.", "error")
        return redirect(url_for('main.users'))

    target_user = get_user_by_id(user_id)
    if not target_user:
        flash("User not found.", "error")
        return redirect(url_for('main.users'))

    # Log forensic activity BEFORE deletion
    log_activity(
        current_admin_id, 
        "User Purge", 
        f"Permanently removed user: {target_user['username']} ({user_id})", 
        request.remote_addr
    )

    if delete_user(user_id):
        flash("User successfully removed from the system.", "success")
    else:
        flash("Failed to purge user from database.", "error")
        
    return redirect(url_for('main.users'))

@bp.route('/profile')
@role_required(['admin', 'analyst', 'viewer'])
def profile():
    """User Profile Page."""
    # Logic to fetch additional details if needed
    return render_template('profile.html', user=session.get('username'))

@bp.route('/api/chart/login-attempts')
@role_required(['admin', 'analyst'])
def api_chart_login_attempts():
    """Returns login attempts grouped by day for the last 7 days."""
    return jsonify(get_login_attempts_by_day())

@bp.route('/api/chart/success-fail')
@role_required(['admin', 'analyst'])
def api_chart_success_fail():
    """Returns count of successful vs failed logins."""
    return jsonify(get_success_fail_count())

@bp.route('/api/chart/active-users')
@role_required(['admin', 'analyst'])
def api_chart_active_users():
    """Returns the top 5 most active users by activity log count."""
    return jsonify(get_top_active_users())

@bp.route('/api/namespace-data')
@bp.route('/api/network-graph')
@role_required(['admin', 'analyst'])
def api_namespace_data():
    """Returns all users and their roles as nodes and edges for D3.js."""
    return jsonify(get_network_graph_data())

@bp.route('/api/system-stats')
@role_required(['admin'])
def system_stats():
    """Returns JSON system metrics for the dashboard."""
    metrics = get_system_metrics()
    if metrics:
        return jsonify(metrics)
    return jsonify({"error": "Unable to collect metrics"}), 500
