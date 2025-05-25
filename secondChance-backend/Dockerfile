FROM node:18.12.1-bullseye-slim

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 3060

CMD ["sh", "-c", "node util/import-mongo/index.js && node app.js"]