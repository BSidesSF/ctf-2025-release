FROM node:20

# Install system dependencies
RUN apt-get update \
    && apt-get install -yq wget curl gnupg libgconf-2-4 ca-certificates xvfb dbus dbus-x11 build-essential --no-install-recommends \
    && apt-get install -yq gconf-service libasound2 libatk1.0-0 libc6 libcairo2 libcurl4-gnutls-dev libcups2 libdbus-1-3 libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 ca-certificates fonts-liberation libappindicator1 libnss3 lsb-release xdg-utils fonts-arphic-ukai fonts-arphic-uming fonts-ipafont-mincho fonts-ipafont-gothic fonts-unfonts-core fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-noto unzip --no-install-recommends \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -

# Install Chrome
RUN apt-get update \
    && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf libxss1 --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Create non-root user with fixed UID/GID
RUN groupadd -g 1001 pptruser \
    && useradd -u 1001 -g 1001 -m -s /bin/bash pptruser

# Set up app directory and permissions
WORKDIR /app
COPY package.json package-lock.json ./
RUN mkdir -p /app/node_modules && chown -R 1001:1001 /app

# Switch to non-root user (using numeric UID/GID)
USER 1001:1001

# Set environment variables
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD true
ENV DISPLAY :99

# Install app dependencies
RUN npm install

# Copy remaining app files
COPY --chown=1001:1001 extension ./extension
COPY --chown=1001:1001 index.js ./
COPY --chown=1001:1001 ChromeEnterprisePolicy.json /etc/chromium/policies/managed/
COPY --chown=1001:1001 ChromeEnterprisePolicy.json /etc/opt/chrome/policies/managed/
COPY --chown=1001:1001 ChromeEnterprisePolicy.json /etc/opt/chrome_for_testing/policies/managed/

# Expose port
EXPOSE 3003

# Run the app
COPY --chown=1001:1001 start.sh /app/start.sh
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
