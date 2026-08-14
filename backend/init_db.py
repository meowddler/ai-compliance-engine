from backend.database import engine, Base
from backend.models import models  # noqa: F401 — import so tables register

Base.metadata.create_all(bind=engine)
print("Database tables created.")