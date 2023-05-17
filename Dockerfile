FROM node:alpine3.17

WORKDIR /app

COPY package.json .

RUN npm install

COPY . .

RUN npx prisma generate

CMD ["npm", "run", "start:dev"]
