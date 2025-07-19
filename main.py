from fastapi import FastAPI

app = FastAPI(
    title="CVE Watcher",
    description="A FastAPI application for monitoring CVE vulnerabilities",
    version="0.1.0",
)


@app.get("/")
async def read_root():
    return {"message": "Welcome to CVE Watcher!", "version": "0.1.0"}


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "cvewatcher"}


@app.get("/cve/{cve_id}")
async def get_cve(cve_id: str):
    return {
        "cve_id": cve_id,
        "status": "placeholder",
        "message": f"Information for {cve_id} will be implemented here",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
