# syntax=docker/dockerfile:1
FROM python:3.10-alpine
#WORKDIR /code
WORKDIR /usr/src/app
#ENV FLASK_APP=app.py
#ENV FLASK_RUN_HOST=0.0.0.0
#RUN apk add --no-cache gcc musl-dev linux-headers
RUN apk update && apk add --no-cache \
    bash \
    postgresql-client
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
#EXPOSE 5000
COPY . .
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]