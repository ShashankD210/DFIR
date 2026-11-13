FROM python:3.13-slim

WORKDIR /app
COPY server.py /app/server.py
RUN mkdir -p /app/data

ENV PORT=8080
EXPOSE 8080
CMD ["python", "/app/server.py"]
