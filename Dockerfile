FROM python:3.12-slim

# p7zip for edge-case archives (AES zips, exotic formats)
RUN apt-get update && \
    apt-get install -y --no-install-recommends p7zip-full && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml requirements.txt ./
COPY history_search/ history_search/

RUN pip install --no-cache-dir .[portable]

EXPOSE 8888
VOLUME ["/evidence"]

# In Docker the analyst's browser reaches the server through the bridge
# network, so the server sees a non-loopback remote_addr. Mutating endpoints
# default-deny non-loopback; --allow-remote tells the server this is expected
# (the same-origin CSRF check still applies). Pin --browse-root to /evidence
# so /api/browse cannot read other paths in the container.
ENTRYPOINT ["python", "-m", "history_search.server"]
CMD ["--host", "0.0.0.0", "--port", "8888", "--allow-remote", "--browse-root", "/evidence"]
