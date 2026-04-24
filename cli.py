import click
from flask.cli import with_appcontext
from models import (
    register_user, assign_role, reset_password, 
    get_activity_logs, get_anomalies, toggle_user_active,
    get_user_by_id
)
from config import test_connection

def register_commands(app):
    """Registers custom CLI commands to the Flask app."""
    
    @app.cli.command("create-user")
    @click.argument("username")
    @click.argument("email")
    @click.argument("password")
    @with_appcontext
    def create_user_command(username, email, password):
        """Creates a new user via the CLI."""
        success, message = register_user(username, email, password)
        if success:
            click.echo(f"Success: User '{username}' created.")
        else:
            click.echo(f"Error: {message}")

    @app.cli.command("assign-role")
    @click.argument("username")
    @click.argument("role_name")
    @with_appcontext
    def assign_role_command(username, role_name):
        """Assigns a role to a user via the CLI."""
        success, message = assign_role(username, role_name)
        if success:
            click.echo(f"Success: {message}")
        else:
            click.echo(f"Error: {message}")

    @app.cli.command("reset-password")
    @click.argument("username")
    @click.argument("newpassword")
    @with_appcontext
    def reset_password_command(username, newpassword):
        """Resets a user's password."""
        success, message = reset_password(username, newpassword)
        if success:
            click.echo(f"Success: Password for '{username}' has been reset.")
        else:
            click.echo(f"Error: {message}")

    @app.cli.command("show-logs")
    @click.argument("username")
    @with_appcontext
    def show_logs_command(username):
        """Prints formatted activity logs for a user."""
        logs = get_activity_logs(username)
        if not logs:
            click.echo(f"No logs found for user '{username}'.")
            return
        
        click.echo(f"{'Timestamp':<20} | {'Action':<20} | {'Resource':<20} | {'IP Address':<15}")
        click.echo("-" * 85)
        for log in logs:
            # Formatting timestamp
            ts = log['created_at'].strftime('%Y-%m-%d %H:%M') if log['created_at'] else 'N/A'
            click.echo(f"{ts:<20} | {log['action']:<20} | {log['resource']:<20} | {log['ip_address']:<15}")

    @app.cli.command("check-anomalies")
    @with_appcontext
    def check_anomalies_command():
        """Prints all unresolved security anomalies."""
        anomalies = get_anomalies()
        if not anomalies:
            click.echo("System Secure: No unresolved anomalies detected.")
            return
        
        click.echo(f"{'Detected At':<20} | {'Type':<15} | {'Severity':<10} | {'User/IP':<20}")
        click.echo("-" * 75)
        for anomaly in anomalies:
            ts = anomaly['flagged_at'].strftime('%Y-%m-%d %H:%M') if anomaly['flagged_at'] else 'N/A'
            user_ip = f"{anomaly['username'] or 'N/A'} / {anomaly['ip_address']}"
            click.echo(f"{ts:<20} | {anomaly['type']:<15} | {anomaly['severity']:<10} | {user_ip:<20}")

    @app.cli.command("deactivate-user")
    @click.argument("username")
    @with_appcontext
    def deactivate_user_command(username):
        """Toggles the 'is_active' status for a user."""
        from models import get_all_users
        users = get_all_users()
        user = next((u for u in users if u['username'] == username), None)
        
        if user:
            if toggle_user_active(user['id']):
                click.echo(f"Success: Status of '{username}' toggled.")
            else:
                click.echo(f"Error: Failed to toggle status for '{username}'.")
        else:
            click.echo(f"Error: User '{username}' not found.")

    @app.cli.command("test-db")
    @with_appcontext
    def test_db_command():
        """Tests the database connection."""
        test_connection()

    @app.cli.command("sys-health")
    @with_appcontext
    def sys_health_command():
        """Prints real-time OS resource usage (CPU/RAM/Uptime)."""
        from os_monitor import get_system_metrics
        metrics = get_system_metrics()
        if not metrics:
            click.echo("Error: Unable to collect system metrics.")
            return
            
        click.echo("=== SYSTEM HEALTH DIAGNOSTICS ===")
        click.echo(f"{'Platform':<15}: {metrics['os']}")
        click.echo(f"{'CPU Usage':<15}: {metrics['cpu']}")
        click.echo(f"{'Memory Usage':<15}: {metrics['memory']}")
        click.echo(f"{'System Uptime':<15}: {metrics['uptime']}")
        click.echo(f"{'Active Procs':<15}: {metrics['processes']}")
        click.echo(f"{'Timestamp':<15}: {metrics['timestamp']}")
        click.echo("-" * 33)
