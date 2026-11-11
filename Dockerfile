FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CHOKIDAAR_MODEL=/app/models/model.joblib

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy/ proxy/
COPY ml/ ml/

# Train once at build time so the container loads the saved model on start.
RUN python -m ml.train --out "$CHOKIDAAR_MODEL"

COPY dashboard/ dashboard/

RUN useradd --system --no-create-home --uid 10001 chokidaar \
    && mkdir -p /data \
    && chown chokidaar:chokidaar /data
USER chokidaar

EXPOSE 8080 8081

CMD ["uvicorn", "proxy.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-server-header", "--no-date-header"]
