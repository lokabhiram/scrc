from flask import Flask, render_template, request, redirect, url_for, session, flash
from models import db, Admin, User, Influencer, Sponsor, Campaign
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.exc import IntegrityError
from flask_migrate import Migrate
import os
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'Zi9iSTTniKKJfIV3dEX72A'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///myproject.db"

db.init_app(app)
migrate = Migrate(app, db)
app.app_context().push()

@app.route("/")
def first():
    return render_template("welcome.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")
    if request.method == "POST":
        try:
            admin_id = request.form.get("admin_id")
            password = request.form.get("password")

            admin = Admin.query.filter_by(admin=admin_id).first()
            if admin and check_password_hash(admin.password, password):
                session['logged_in'] = True
                session['username'] = admin_id
                return redirect(url_for('admin_dashboard'))
            else:
                error = 'Invalid admin ID or password. Try again'
                return render_template('admin_login.html', error=error)

        except Exception as e:
            error = 'An error occurred. Please contact the administrator.'
            return render_template("admin_login.html", error=error)

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user_type = request.form.get('user_type')

        user = User.query.filter_by(username=username, user_type=user_type).first()

        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['username'] = username
            session['user_type'] = user_type
            if user_type == 'influencer':
                return redirect(url_for('influencer_profile'))
            elif user_type == 'sponsor':
                return redirect(url_for('sponsor_profile'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('user_login'))

    return render_template('user_login.html')

@app.route('/register/influencer', methods=['POST'])
def register_influencer():
    username = request.form['username']
    password = request.form['password']
    platform_presence = ','.join(request.form.getlist('platform_presence'))

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_influencer = Influencer(username=username, password=hashed_password, user_type='influencer', platform_presence=platform_presence)

    try:
        db.session.add(new_influencer)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('user_login'))
    except IntegrityError:
        db.session.rollback()
        flash('Username already exists. Please log in.', 'error')
        return redirect(url_for('user_login'))

@app.route('/user/influencer_register')
def influencer_register_page():
    return render_template('influencer_register.html')

@app.route('/register/sponsor', methods=['POST'])
def register_sponsor():
    username = request.form['username']
    password = request.form['password']
    industry = request.form['industry']

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_sponsor = Sponsor(username=username, password=hashed_password, user_type='sponsor', industry=industry)

    try:
        db.session.add(new_sponsor)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('user_login'))
    except IntegrityError:
        db.session.rollback()
        flash('Username already exists. Please log in.', 'error')
        return redirect(url_for('user_login'))

@app.route('/user/sponsor_register')
def sponsor_register_page():
    return render_template('sponsor_register.html')

@app.route('/influencer/profile')
def influencer_profile():
    if 'logged_in' in session and session.get('user_type') == 'influencer':
        username = session.get('username')
        return render_template('influencer_profile.html', username=username)
    else:
        return redirect(url_for('user_login'))

@app.route('/sponsor/profile')
def sponsor_profile():
    if 'logged_in' in session and session.get('user_type') == 'sponsor':
        username = session.get('username')
        sponsor = Sponsor.query.filter_by(username=username).first()
        if sponsor:
            campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).order_by(Campaign.date.desc()).limit(2).all()
            return render_template('sponsor_profile.html', username=username, campaigns=campaigns)
        else:
            flash('Error: Sponsor not found.', 'error')
            return redirect(url_for('user_login'))
    else:
        return redirect(url_for('user_login'))

@app.route('/sponsor/campaigns', methods=['GET', 'POST']) 
def sponsor_campaigns():
    if 'logged_in' in session and session.get('user_type') == 'sponsor':
        if request.method == 'POST':
            # Handle campaign creation
            title = request.form['title']
            description = request.form['description']
            image = request.form['image'] 
            niche = request.form['niche']
            date = request.form['date'] 

            # Get the logged-in sponsor's ID from the database
            sponsor = Sponsor.query.filter_by(username=session['username']).first()
            
            if sponsor:  # Check if a sponsor was found
                sponsor_id = sponsor.id

                new_campaign = Campaign(
                    title=title, 
                    description=description, 
                    image=image, 
                    niche=niche, 
                    date=date, 
                    sponsor_id=sponsor_id 
                )
                try:
                    db.session.add(new_campaign)
                    db.session.commit()
                    flash('Campaign added successfully!', 'success')
                    return redirect(url_for('sponsor_campaigns'))
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error adding campaign: {str(e)}', 'error')
                    return redirect(url_for('sponsor_campaigns'))

            else: 
                flash('Error: Could not find sponsor. Please log in again.', 'error')
                return redirect(url_for('user_login'))

        return render_template('sponsor_campaign.html')
    else:
        return redirect(url_for('user_login'))

@app.route("/admin/dashboard")
def admin_dashboard():
    if 'logged_in' in session and session.get('username'):
        return render_template("admin_dashboard.html")
    else:
        return redirect(url_for('admin_login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('user_login'))

@app.route('/admin_logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    app.run(debug=True)
