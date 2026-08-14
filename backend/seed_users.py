from backend.database import SessionLocal
from backend.models.models import User
from backend.core.auth import hash_password


def seed():
    db = SessionLocal()
    if db.query(User).count() > 0:
        print("Users already exist, skipping.")
        db.close()
        return

    users = [
        User(username="admin", hashed_password=hash_password("admin123"), role="Admin"),
        User(username="auditor1", hashed_password=hash_password("auditor123"), role="Auditor"),
        User(username="analyst1", hashed_password=hash_password("analyst123"), role="Analyst"),
    ]

    db.add_all(users)
    db.commit()
    db.close()
    print("Seeded 3 users: admin/admin123, auditor1/auditor123, analyst1/analyst123")


if __name__ == "__main__":
    seed()