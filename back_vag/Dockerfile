# back/Dockerfile

# 1. Choix de l'image de base (légère et officielle)
FROM python:3.9-slim

# 2. Désactive le buffering de Python pour des logs immédiats
ENV PYTHONUNBUFFERED=1

# 3. Définir le dossier de travail à l'intérieur du conteneur
WORKDIR /app

# Installer Vagrant (et ses dépendances système si besoin)
RUN apt-get update \
    && apt-get install -y --no-install-recommends vagrant \
    && rm -rf /var/lib/apt/lists/*
# 4. Copier et installer les dépendances Python
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copier le code source dans le conteneur
COPY . ./

# 6. Spécifier la variable d'environnement FLASK_APP
ENV FLASK_APP=app.py

# 7. Exposer le port d'écoute de l'application Flask
EXPOSE 5000

# 8. Commande de démarrage avec flask run pour écouter sur toutes les interfaces
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]