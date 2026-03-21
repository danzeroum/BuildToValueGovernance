# BuildToValue Public Benchmark Runner
FROM python:3.12-slim

WORKDIR /bench

COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[all]" || pip install --no-cache-dir -e .

COPY . .

ENTRYPOINT ["python", "runner.py"]
CMD ["--adapters", "btv"]
