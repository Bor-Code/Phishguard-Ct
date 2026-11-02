FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/app/data/phishguard.db \
    WATCHLIST_PATH=/app/config/brands.json

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
COPY data ./data
COPY reports ./reports

RUN pip install --no-cache-dir . && \
    useradd --create-home --shell /bin/bash phishguard && \
    chown -R phishguard:phishguard /app

USER phishguard

ENTRYPOINT ["phishguard"]
CMD ["monitor"]
