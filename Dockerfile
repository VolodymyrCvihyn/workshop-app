FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Встановлення залежностей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копіюємо код
COPY . .

# Папка для бази даних (ми змонтуємо її ззовні як volume)
RUN mkdir -p /data
ENV DB_PATH=/data/db.sqlite

# Секретний ключ для Flask (можна перевизначити змінною оточення)
ENV SECRET_KEY=change-me-to-something-random

EXPOSE 8000

# Запускаємо через gunicorn
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
