FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Copy source code and configuration first
COPY . .

# Install dependencies (this will also run the prepare script -> tsc)
RUN npm install

# Build the application (potentially redundant now, but kept for consistency)
# If the prepare script already builds, this might be removable.
# RUN npm run build  <-- Commented out as prepare script likely runs build

# Create data directory
RUN mkdir -p /app/calendar-data

# Set permissions for the data directory
RUN chown -R node:node /app/calendar-data

# Switch to non-root user
USER node

# Start the server
CMD ["node", "dist/index.js"]