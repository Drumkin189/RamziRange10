FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping curl \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir flask pymysql requests lxml

WORKDIR /app

# AngularJS vendored locally: CSTI needs a real client-side template engine, and
# pulling it from a CDN sends the crawler off-box (that cost hours on RR8).
RUN curl -fsSL -o /app/angular.min.js \
      https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js \
 && test -s /app/angular.min.js

COPY app.py /app/app.py

RUN echo 'RR10{path_traversal_flag}' > /flag.txt

ENV DB_PASSWORD=Qu33bl3r0ne \
    AWS_SECRET_ACCESS_KEY=RR10flag/EXAMPLE/secret

EXPOSE 5000
CMD ["python", "app.py"]
