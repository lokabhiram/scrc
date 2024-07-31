from flask import Flask, request, redirect, url_for, flash, session, render_template
from models import db, Admin, User, Influencer, Sponsor, Campaign, AdRequest
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
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id  # Set user_id for both influencer and sponsor
            session['username'] = user.username
            session['user_type'] = user.user_type

            flash('You were successfully logged in', 'success')
            if user.user_type == 'sponsor':
                return redirect(url_for('sponsor_profile'))
            elif user.user_type == 'influencer':
                return redirect(url_for('influencer_profile'))
        else:
            flash('Invalid credentials', 'danger')

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
        sponsor = Sponsor.query.filter_by(username=session['username']).first()
        if sponsor:
            if request.method == 'POST':
                # Handle campaign creation
                title = request.form['title']
                description = request.form['description']
                image = request.form['image'] 
                niche = request.form['niche']
                date = request.form['date'] 

                new_campaign = Campaign(
                    title=title,
                    description=description,
                    image=image,
                    niche=niche,
                    date=date,
                    sponsor_id=sponsor.id
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

            # Fetch the sponsor's campaigns
            campaigns = Campaign.query.filter_by(sponsor_id=sponsor.id).all()
            return render_template('sponsor_campaign.html', campaigns=campaigns)

    return redirect(url_for('user_login'))

@app.route('/sponsor/ad_request', methods=['POST'])
def add_ad_request():
    print(session)  # Debug print

    if 'logged_in' in session and session.get('user_type') == 'sponsor':
        campaign_id = request.form.get('campaign_id')
        ad_name = request.form.get('ad_name')
        ad_description = request.form.get('ad_description')
        ad_terms = request.form.get('ad_terms')
        budget = request.form.get('budget')

        # Assuming the logged-in user is a sponsor
        sponsor = Sponsor.query.get(session['user_id'])

        # Create the new ad request
        new_ad_request = AdRequest(
            influencer_id=session['user_id'],  # This should be the sponsor's ID
            campaign_id=campaign_id,
            ad_name=ad_name,
            ad_description=ad_description,
            ad_terms=ad_terms,
            budget=budget
        )

        db.session.add(new_ad_request)
        db.session.commit()

        flash('Ad request created successfully!', 'success')
        return redirect(url_for('sponsor_campaigns'))

    flash('You must be logged in as a sponsor to create an ad request', 'danger')
    return redirect(url_for('login'))

@app.route('/sponsor/find', methods=['GET', 'POST'])
def sponsor_find_page():
    if 'logged_in' in session and session.get('user_type') == 'sponsor':
        if request.method == 'POST':
            search_type = request.form.get('search_type')
            keyword = request.form.get('keyword')

            if search_type == 'campaigns':
                results = Campaign.query.filter(
                    (Campaign.title.ilike(f'%{keyword}%')) | 
                    (Campaign.description.ilike(f'%{keyword}%')) | 
                    (Campaign.niche.ilike(f'%{keyword}%'))
                ).all()
            elif search_type == 'influencers':
                results = Influencer.query.filter(
                    (Influencer.username.ilike(f'%{keyword}%')) | 
                    (Influencer.platform_presence.ilike(f'%{keyword}%'))
                ).all()
            else:
                results = []

            return render_template('sponsor_find.html', results=results, search_type=search_type)

        return render_template('sponsor_find.html', results=[], search_type=None)
    return redirect(url_for('user_login'))



@app.route('/sponsor/campaign/<int:campaign_id>')
def view_campaign(campaign_id):
    if 'logged_in' in session and session.get('user_type') == 'sponsor':
        campaign = Campaign.query.get(campaign_id)
        if campaign:
            return render_template('view_campaign.html', campaign=campaign)
        else:
            flash('Campaign not found.', 'error')
            return redirect(url_for('sponsor_campaigns'))
    else:
        return redirect(url_for('user_login'))



@app.route('/ad_request/create', methods=['POST'])
def create_ad_request():
    if 'logged_in' in session and session.get('user_type') == 'influencer':
        influencer = Influencer.query.filter_by(username=session['username']).first()
        if influencer:
            campaign_id = request.form['campaign_id']
            new_ad_request = AdRequest(influencer_id=influencer.id, campaign_id=campaign_id)
            db.session.add(new_ad_request)
            db.session.commit()
            flash('Ad request submitted successfully!', 'success')
            return redirect(url_for('influencer_profile'))
    return redirect(url_for('user_login'))

@app.route('/sponsor/ad_requests')
def view_ad_requests():
    if 'logged_in' in session and session.get('user_type') == 'sponsor':
        sponsor = Sponsor.query.filter_by(username=session['username']).first()
        if sponsor:
            ad_requests = AdRequest.query.join(Campaign).filter(Campaign.sponsor_id == sponsor.id).all()
            return render_template('view_ad_requests.html', ad_requests=ad_requests)
    return redirect(url_for('user_login'))

@app.route('/ad_request/<int:request_id>/accept')
def accept_ad_request(request_id):
    if 'logged_in' in session and session.get('user_type') == 'sponsor':
        ad_request = AdRequest.query.get(request_id)
        if ad_request:
            ad_request.status = 'Accepted'
            db.session.commit()
            flash('Ad request accepted!', 'success')
            return redirect(url_for('view_ad_requests'))
    return redirect(url_for('user_login'))

@app.route('/ad_request/<int:request_id>/reject')
def reject_ad_request(request_id):
    if 'logged_in' in session and session.get('user_type') == 'sponsor':
        ad_request = AdRequest.query.get(request_id)
        if ad_request:
            ad_request.status = 'Rejected'
            db.session.commit()
            flash('Ad request rejected!', 'success')
            return redirect(url_for('view_ad_requests'))
    return redirect(url_for('user_login'))

@app.route('/sponsor/find')
def find_page():
    return render_template('find.html')


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
