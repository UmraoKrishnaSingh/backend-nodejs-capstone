
FROM node:18.12.1-bullseye-slim

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

# Expose port (if needed)
EXPOSE 9000

# Run the application
CMD ["node", "index.js"]
