from flask import Blueprint, request, jsonify
from flask_restful import Resource
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from models import db, User, LoginSession, Payment, SMTPSettings, VoipSettings, Config , HistoryLog #, APIKey
import uuid
from datetime import datetime, timedelta
from flask_restful import Api

api_bp = Blueprint("api", __name__, url_prefix="/api")
api = Api(api_bp)

class LoginAPI(Resource):
    def post(self):
        data = request.json
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            return {"message": "Invalid credentials"}, 401
            
        # Admins have unlimited logins
        # if user.role == "admin":
        #     login_user(user)
        #     return {"message": "Admin Login successful!"}, 200

        if user and user.check_password(password):
            active_sessions = LoginSession.query.filter_by(user_id=user.id).count()
            if (active_sessions or 0) >= (user.max_logins or 1):
                return {"message": "Maximum login limit reached"}, 403

            # Generate new login token
            new_token = str(uuid.uuid4())
            login_token = LoginSession(user_id=user.id, session_token=new_token)
            db.session.add(login_token)
            db.session.commit()

            login_user(user)
            return {"message": "Login successful", "token": new_token}, 200
        

class LogoutAPI(Resource):
    def post(self):
        token = request.headers.get("Authorization")
        if token:
            LoginSession.query.filter_by(session_token=token).delete()
            db.session.commit()
            logout_user()
            return {"message": "Logout successful"}, 200

        return {"message": "Invalid request"}, 400

# User Dashboard API
class UserDashboardAPI(Resource):
    def get(self):
        # Extract token from the Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return {"message": "Missing or invalid token"}, 401
        
        token = auth_header.replace("Bearer ", "").strip()

        # Verify the token in the database
        login_token = LoginSession.query.filter_by(session_token=token).first()
        if not login_token:
            return {"message": "Invalid or expired token"}, 401
        
        user = User.query.get(login_token.user_id)
        if not user:
            return {"message": "User not found"}, 404

        return {
            "username": user.username,
            "user_email": user.email,
            "user_phone": user.phone_number,
            "payment_status": user.is_paid,
            "days_remaining": (user.payment_due_date - datetime.utcnow().date()).days if user.payment_due_date else "N/A",
            "max_logins": user.max_logins,
            "sms_opt_in": user.sms_opt_in,
        }, 200

# Admin API
class AdminDashboardAPI(Resource):
    def get(self):
        # Extract token from the Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return {"message": "Missing or invalid token"}, 401
        
        token = auth_header.replace("Bearer ", "").strip()

        # Verify the token in the database
        login_token = LoginSession.query.filter_by(session_token=token).first()
        if not login_token:
            return {"message": "Invalid or expired token"}, 401
        
        user = User.query.get(login_token.user_id)
        if not user:
            return {"message": "User not found"}, 404
        if user.role != "admin":
            return {"message": "Unauthorized"}, 401
        
        users = User.query.all()
        user_list = [
            {
                "id": user.id,
                "username": user.username,
                "role": user.role,
                "payment_status": user.is_paid,
                "notifications": user.notifications,
                "email_verified": user.email_verified,
                "days_remaining": (user.payment_due_date - datetime.utcnow().date()).days if user.payment_due_date else "N/A",
                "max_logins": user.max_logins,
                "sms_opt_in": user.sms_opt_in,
            }
            for user in users
        ]
        return {"users": user_list}, 200

# Payment API
class ProcessPaymentAPI(Resource):
    @login_required
    def post(self):
        data = request.json
        amount = float(data.get("amount", 30.00)) * 100  # Convert to cents
        token = data.get("stripeToken")

        if not current_user.stripe_enabled:
            return {"message": "Stripe payments are disabled for this user"}, 403

        try:
            charge = stripe.Charge.create(
                amount=int(amount),
                currency="usd",
                description=f"Payment for {current_user.username}",
                source=token,
            )
            current_user.is_paid = True
            current_user.payment_due_date = datetime.utcnow().date() + timedelta(days=30)
            db.session.commit()
            log_action(current_user.id, "Processed payment via API")
            return {"message": "Payment successful"}, 200
        except stripe.error.StripeError as e:
            return {"message": f"Payment failed: {e.user_message}"}, 400

# History Log API
class HistoryLogAPI(Resource):
    # @login_required
    def get(self):
        # Extract token from the Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return {"message": "Missing or invalid token"}, 401
        
        token = auth_header.replace("Bearer ", "").strip()

        # Verify the token in the database
        login_token = LoginSession.query.filter_by(session_token=token).first()
        if not login_token:
            return {"message": "Invalid or expired token"}, 401
        
        user = User.query.get(login_token.user_id)
        if not user:
            return {"message": "User not found"}, 404
        if user.role != "admin":
            return {"message": "Unauthorized"}, 401

        logs = HistoryLog.query.order_by(HistoryLog.timestamp.desc()).all()
        log_list = [
            {
                "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                "action": log.action,
                "user": log.user.username,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
            }
            for log in logs
        ]
        return {"history_logs": log_list}, 200

# API Key Management
class GenerateAPIKeyAPI(Resource):
    @login_required
    def post(self):
        if current_user.role != "admin":
            return {"message": "Unauthorized"}, 401

        user_id = request.json.get("user_id")
        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        new_key = APIKey(user_id=user.id)
        db.session.add(new_key)
        db.session.commit()
        log_action(current_user.id, f"Generated API Key for {user.username}")
        return {"message": "API Key generated", "api_key": new_key.key}, 200

# Register API Endpoints
api.add_resource(LoginAPI, "/login")
api.add_resource(LogoutAPI, "/logout")
api.add_resource(UserDashboardAPI, "/user/dashboard")
api.add_resource(AdminDashboardAPI, "/admin/dashboard")
api.add_resource(ProcessPaymentAPI, "/payment")
api.add_resource(HistoryLogAPI, "/admin/history")
api.add_resource(GenerateAPIKeyAPI, "/admin/generate_api_key")