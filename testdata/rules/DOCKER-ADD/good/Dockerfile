FROM python:3.12-slim
WORKDIR /src
COPY . /src
# ADD is only used for a download with a pinned checksum.
ADD --checksum=sha256:24454f830cdb571e2c4ad154__JOIN__81119c43b3cafd48dd869a9b2945d1036d1dc68d https://example.com/tool.tar.gz /tmp/tool.tar.gz
CMD ["python", "app.py"]
