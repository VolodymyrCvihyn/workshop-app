FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    TZ=Europe/Kyiv

WORKDIR /app

# Встановлюємо залежності
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копіюємо код
COPY . .

EXPOSE 8000

CMD ["python", "app.py"]
