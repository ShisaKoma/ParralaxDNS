FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/data/domain_inventory.sqlite3

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY app ./app
COPY alembic ./alembic

RUN pip install --no-cache-dir . \
    && addgroup --system app \
    && adduser --system --ingroup app --home /app app \
    && mkdir /data \
    && chown -R app:app /app /data

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8000/api/domains', timeout=3)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
