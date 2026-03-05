FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    sqlalchemy \
    psycopg2-binary \
    python-jose \
    bcrypt \
    python-multipart \
    langchain-groq \
    langchain-community \
    duckduckgo-search \
    python-dotenv \
    numpy \
    scikit-learn \
    scipy

COPY . .

CMD uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}
