FROM python:3.12-slim
WORKDIR /app
COPY balloni_server.py .
RUN useradd -r -u 10001 bal && mkdir /data && chown bal /data
USER bal
ENV DATA_DIR=/data PORT=8090 BIND=0.0.0.0
CMD ["python", "-I", "balloni_server.py"]
