"""PromptShield 데이터 준비 스크립트 (1회 실행)

외부 공개 데이터를 내려받아 이 프로젝트가 쓰는 형태로 가공하고,
FAISS 벡터 인덱스까지 만들어 둡니다. 산출물은 git 에 커밋하므로
배포 환경(Streamlit Cloud)에서는 다시 실행할 필요가 없습니다.

수집 대상
  1. 정형   : HuggingFace `deepset/prompt-injections` (Apache-2.0)
              -> LLM 게이트웨이 접근 로그 CSV 로 합성
  2. 비정형 : MITRE ATLAS `dist/ATLAS.yaml` (Approved for Public Release)
              -> 전술/기법/완화책/사례 를 문단화한 마크다운
  3. 비정형 : NIST AI RMF 1.0 PDF (미국 정부 저작물)

실행:
    python prepare_data.py
    python prepare_data.py --skip-index   # 임베딩 없이 원본만 준비
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import random
import sys
import textwrap
from pathlib import Path

import pandas as pd
import requests
import yaml

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"
INDEX_DIR = DATA_DIR / "faiss_index"
LOG_CSV = DATA_DIR / "llm_gateway_logs.csv"

HF_PARQUET = (
    "https://huggingface.co/api/datasets/deepset/prompt-injections"
    "/parquet/default/{split}/0.parquet"
)
ATLAS_YAML = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
NIST_PDFS = [
    ("nist_ai_rmf_100_1.pdf", "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf"),
    ("nist_ai_600_1_genai.pdf", "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf"),
]

# 로그 합성에 쓰는 운영 메타데이터 후보군
TENANTS = ["fin-core", "cs-bot", "dev-copilot", "hr-assist"]
ENDPOINTS = ["/v1/chat", "/v1/agent", "/v1/embed"]
MODELS = ["gpt-4.1-mini", "claude-sonnet", "llama-3-70b"]
COUNTRIES = ["KR", "US", "JP", "CN", "RU", "DE", "SG", "BR"]

# injection_label=1 인 요청에 배정할 ATLAS 기법 (실제 ATLAS ID)
ATTACK_TECHNIQUES = [
    "AML.T0051.000",  # LLM Prompt Injection: Direct
    "AML.T0051.001",  # LLM Prompt Injection: Indirect
    "AML.T0054",      # LLM Jailbreak
    "AML.T0057",      # LLM Data Leakage
    "AML.T0056",      # Extract LLM System Prompt
]


def log(msg: str) -> None:
    print(f"[prepare] {msg}", flush=True)


def fetch(url: str, timeout: int = 60) -> bytes:
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "PromptShield/1.0"})
    resp.raise_for_status()
    return resp.content


# ---------------------------------------------------------------------------
# 1. 정형 데이터: LLM 게이트웨이 접근 로그
# ---------------------------------------------------------------------------
def build_gateway_logs() -> pd.DataFrame:
    """HF prompt-injections 를 시드로 운영 로그 형태의 CSV 를 합성합니다."""
    frames = []
    for split in ("train", "test"):
        url = HF_PARQUET.format(split=split)
        log(f"HF parquet 다운로드: {split}")
        frames.append(pd.read_parquet(io.BytesIO(fetch(url))))
    seed_df = pd.concat(frames, ignore_index=True)
    log(f"시드 데이터 {len(seed_df)}행 (컬럼: {list(seed_df.columns)})")

    # 재현 가능하도록 고정 시드 사용
    rng = random.Random(20260825)

    rows = []
    start = pd.Timestamp("2026-07-26 00:00:00")
    for i, seed in seed_df.iterrows():
        text = str(seed["text"]).strip()
        label = int(seed["label"])

        # 공격 요청일수록 탐지기 점수가 높게 나오도록 분포를 분리하되,
        # 오탐/미탐이 섞이게 해서 분석할 거리를 만든다.
        if label == 1:
            score = min(1.0, max(0.0, rng.gauss(0.78, 0.16)))
        else:
            score = min(1.0, max(0.0, rng.gauss(0.22, 0.15)))

        if score >= 0.75:
            action = "blocked"
        elif score >= 0.45:
            action = "flagged"
        else:
            action = "allowed"

        prompt_tokens = max(8, len(text) // 4)
        rows.append({
            "request_id": "req_" + hashlib.md5(f"{i}{text[:32]}".encode()).hexdigest()[:12],
            "timestamp": start + pd.Timedelta(minutes=rng.randint(0, 30 * 24 * 60)),
            "tenant": rng.choices(TENANTS, weights=[4, 3, 2, 1])[0],
            "user_id": f"u{rng.randint(1000, 1199)}",
            "endpoint": rng.choices(ENDPOINTS, weights=[6, 3, 1])[0],
            "model": rng.choices(MODELS, weights=[5, 3, 2])[0],
            "prompt_excerpt": textwrap.shorten(text, width=180, placeholder=" ..."),
            "injection_label": label,
            "detector_score": round(score, 3),
            "action": action,
            "latency_ms": rng.randint(180, 4200),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": 0 if action == "blocked" else rng.randint(12, 900),
            "atlas_technique": rng.choice(ATTACK_TECHNIQUES) if label == 1 else "",
            "source_country": rng.choices(COUNTRIES, weights=[8, 5, 2, 3, 2, 2, 2, 1])[0],
        })

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# 2. 비정형 데이터: MITRE ATLAS
# ---------------------------------------------------------------------------
def build_atlas_docs() -> list[Path]:
    """ATLAS.yaml 을 사람이 읽는 마크다운 문서로 펼칩니다."""
    log("MITRE ATLAS YAML 다운로드")
    raw = yaml.safe_load(fetch(ATLAS_YAML).decode("utf-8"))

    # ATLAS.yaml 은 matrices 아래에 tactics/techniques 를, 최상위에 그 외를 둡니다.
    buckets: dict[str, list] = {
        "tactics": [], "techniques": [], "mitigations": [], "case-studies": [],
    }

    def absorb(container: dict) -> None:
        for key in buckets:
            items = container.get(key) or []
            if isinstance(items, list):
                buckets[key].extend(items)

    absorb(raw)
    for matrix in raw.get("matrices", []) or []:
        absorb(matrix)

    written = []
    for kind, items in buckets.items():
        if not items:
            log(f"  ! {kind}: 항목 없음 (스키마 변경 가능성)")
            continue

        lines = [f"# MITRE ATLAS — {kind}", ""]
        for item in items:
            if not isinstance(item, dict):
                continue
            tid = item.get("id", "")
            name = item.get("name", "")
            lines.append(f"## [{tid}] {name}")
            desc = (item.get("description") or "").strip()
            if desc:
                lines.append(desc)

            # 사례 연구는 어떤 기법을 썼는지가 핵심 정보다.
            for proc in item.get("procedure", []) or []:
                if isinstance(proc, dict):
                    lines.append(
                        f"- 사용 기법 {proc.get('technique','')}: "
                        f"{(proc.get('description') or '').strip()}"
                    )
            for field in ("target", "actor", "case-study-type", "incident-date"):
                if item.get(field):
                    lines.append(f"- {field}: {item[field]}")
            lines.append("")

        path = KNOWLEDGE_DIR / f"atlas_{kind.replace('-', '_')}.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        log(f"  {path.name}: {len(items)}개 항목, {path.stat().st_size // 1024}KB")
        written.append(path)

    return written


# ---------------------------------------------------------------------------
# 3. 비정형 데이터: NIST AI RMF PDF
# ---------------------------------------------------------------------------
def fetch_nist_pdfs() -> list[Path]:
    written = []
    for filename, url in NIST_PDFS:
        path = KNOWLEDGE_DIR / filename
        try:
            log(f"NIST PDF 다운로드: {filename}")
            path.write_bytes(fetch(url))
            log(f"  {filename}: {path.stat().st_size // 1024}KB")
            written.append(path)
        except Exception as exc:  # 한쪽이 없어도 나머지로 진행
            log(f"  ! {filename} 실패 ({exc}) — 건너뜁니다")
    return written


# ---------------------------------------------------------------------------
# 4. FAISS 인덱스
# ---------------------------------------------------------------------------
def build_index(api_key: str) -> None:
    from langchain_community.document_loaders import PyPDFLoader
    from langchain_community.vectorstores import FAISS
    from langchain_core.documents import Document
    from langchain_openai import OpenAIEmbeddings
    from langchain_text_splitters import RecursiveCharacterTextSplitter

    docs: list[Document] = []

    for md in sorted(KNOWLEDGE_DIR.glob("*.md")):
        text = md.read_text(encoding="utf-8")
        docs.append(Document(page_content=text, metadata={"source": md.name}))

    for pdf in sorted(KNOWLEDGE_DIR.glob("*.pdf")):
        log(f"PDF 파싱: {pdf.name}")
        for d in PyPDFLoader(str(pdf)).load():
            d.metadata["source"] = pdf.name
            docs.append(d)

    if not docs:
        raise RuntimeError("인덱싱할 문서가 없습니다. 앞 단계를 먼저 실행하세요.")

    splitter = RecursiveCharacterTextSplitter(chunk_size=1200, chunk_overlap=150)
    chunks = splitter.split_documents(docs)
    log(f"청크 {len(chunks)}개 생성 — 임베딩 시작 (수 분 소요)")

    embeddings = OpenAIEmbeddings(model="text-embedding-3-small", api_key=api_key)
    store = FAISS.from_documents(chunks, embedding=embeddings)
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    store.save_local(str(INDEX_DIR))
    log(f"FAISS 인덱스 저장 완료 → {INDEX_DIR}")


def main() -> int:
    parser = argparse.ArgumentParser(description="PromptShield 데이터 준비")
    parser.add_argument("--skip-index", action="store_true", help="임베딩 단계를 건너뜁니다")
    args = parser.parse_args()

    KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)

    df = build_gateway_logs()
    df.to_csv(LOG_CSV, index=False)
    log(f"게이트웨이 로그 저장: {LOG_CSV.name} — {len(df)}행 x {len(df.columns)}열")
    log(f"  공격 비율 {df['injection_label'].mean():.1%} / 차단률 "
        f"{(df['action'] == 'blocked').mean():.1%}")

    build_atlas_docs()
    fetch_nist_pdfs()

    if args.skip_index:
        log("--skip-index 지정됨 — 임베딩 생략")
        return 0

    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        log("! OPENAI_API_KEY 가 없어 인덱싱을 건너뜁니다 (.env 확인)")
        return 1

    build_index(api_key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
