from flask import Flask, jsonify
from models import db, Campaign

app = Flask(__name__)

# Configuration for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myproject.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

@app.route('/')
def print_campaigns():
    campaigns = Campaign.query.all()
    campaign_list = []
    for campaign in campaigns:
        campaign_data = {
            'id': campaign.id,
            'title': campaign.title,
            'description': campaign.description,
            'image': campaign.image,
            'niche': campaign.niche,
            'date': campaign.date,
            'sponsor_id': campaign.sponsor_id,
        }
        campaign_list.append(campaign_data)
    return jsonify(campaign_list)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
