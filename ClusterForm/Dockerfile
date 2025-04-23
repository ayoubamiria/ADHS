# Utiliser Node.js léger
FROM node:18-alpine

# Dossier de travail
WORKDIR /app

# Copier package.json et installer
COPY package*.json ./
RUN npm install

# Copier tout le reste
COPY . .

# Exposer le port du dev-server
EXPOSE 3000

# Lancer react-scripts start (avec le proxy défini dans package.json)
CMD ["npm", "start"]
