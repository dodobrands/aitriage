FROM python:3.12-slim
WORKDIR /app
COPY . .
# ENV API_KEY=... is passed at runtime instead.
ENV SECRETS_DIR=/run/secrets
ENV TOKEN_TTL_SECONDS=3600 PASSWORD_MIN_LENGTH=12
CMD ["python", "app.py"]
