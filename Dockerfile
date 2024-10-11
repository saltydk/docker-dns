FROM python:3.12-alpine

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./

ENTRYPOINT ["python3", "/usr/src/app/main.py"]
