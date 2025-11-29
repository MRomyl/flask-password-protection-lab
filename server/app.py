#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User, UserSchema

user_schema = UserSchema()


class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        # Create new user
        new_user = User(username=username)
        new_user.password_hash = password  # bcrypt hashing happens in setter

        db.session.add(new_user)
        db.session.commit()

        return user_schema.dump(new_user), 200



class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        user = User.query.filter_by(username=username).first()

        if not user or not user.authenticate(password):
            return {"error": "Invalid credentials"}, 401

        
        session["user_id"] = user.id

        return user_schema.dump(user), 200



class Logout(Resource):
    def delete(self):
        session.pop("user_id", None)
        return {}, 204



class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")

        if not user_id:
            return "", 204

        user = User.query.get(user_id)
        if not user:
            return "", 204

        return user_schema.dump(user), 200



class ClearSession(Resource):
    def delete(self):
        session["page_views"] = None
        session["user_id"] = None
        return {}, 204


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(ClearSession, "/clear", endpoint="clear")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
