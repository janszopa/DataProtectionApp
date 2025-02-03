FROM python:3.10-alpine
WORKDIR /usr/src/app
RUN apk update && apk add --no-cache \
    bash \
    postgresql-client
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]