FROM python:3.9
EXPOSE 5000/tcp
WORKDIR /app
COPY requirements.txt .
COPY ./models ./models
COPY ./dataset/malicious_phish.csv ./dataset/malicious_phish.csv
RUN pip install -r requirements.txt
COPY . .
CMD [ "python", "./app.py" ]