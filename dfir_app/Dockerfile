FROM python:3.13-slim

WORKDIR /app
COPY dfir_app/server.py /app/server.py
COPY dfir_app/toolkit_runner.py /app/toolkit_runner.py
COPY dfir_toolkit.py /app/dfir_toolkit.py
RUN mkdir -p /app/data

ENV PORT=8080
ENV DFIR_TOOLKIT_PATH=/app/dfir_toolkit.py
ENV DFIR_CLOUD_OUTPUT=/app/output
EXPOSE 8080
CMD ["python", "/app/server.py"]
