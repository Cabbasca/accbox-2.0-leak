from app import app
from app import models
from app import db
from app import mcapi
from apscheduler.schedulers.background import BackgroundScheduler
from app.routes import routes

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    scheduler = BackgroundScheduler()
    scheduler.add_job(func=mcapi.refresh_accounts, trigger="interval", hours=app.config.get("REFRSH_INTERVAL", 10))
    scheduler.start()
    mcapi.refresh_accounts()

    app.run(debug=app.config.get("DEBUG", False), port=app.config.get("PORT", 5000))
