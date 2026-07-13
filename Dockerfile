FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy source
COPY . .

# Build application
RUN npm run build

# Expose port (assuming Vite/Express default or 3000)
EXPOSE 3000

# Start application
CMD ["npm", "start"]
