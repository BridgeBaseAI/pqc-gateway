FROM python:3.12-slim

# ── 1. Build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake \
        ninja-build \
        libssl-dev \
        build-essential \
        git \
        curl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Build liboqs from main branch (compatible with liboqs-python 0.14.1)
#    We do NOT pin a version tag because 0.14.1 needs functions not in 0.11.0
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON \
    && cmake --build /tmp/liboqs/build \
    && cmake --install /tmp/liboqs/build \
    && rm -rf /tmp/liboqs \
    && ldconfig

# ── 3. Show what .so files were created (helps debug if needed)
RUN find /usr/local/lib -name "liboqs*" -type f

# ── 4. Point liboqs-python directly at our compiled library
#    This stops it from trying to auto-download anything
ENV LD_LIBRARY_PATH=/usr/local/lib \
    OQS_SHARED_LIB=/usr/local/lib/liboqs.so \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── 5. Verify import works before copying app code
RUN python -c "import oqs; print('liboqs OK'); kem = oqs.KeyEncapsulation('ML-KEM-768'); print('ML-KEM-768 OK')"

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
