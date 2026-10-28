FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mirage ./mirage
COPY scripts ./scripts
ENV DB_PATH=/data/mirage.db PORT=8080
VOLUME /data
EXPOSE 8080
CMD ["python", "-m", "mirage"]
