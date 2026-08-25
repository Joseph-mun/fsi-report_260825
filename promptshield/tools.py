"""외부 웹 API 래퍼 (Tavily 웹 검색, NVD CVE 조회)

두 함수 모두 실패를 예외로 던지지 않고 문자열로 돌려줍니다.
웹 API 장애가 그래프 전체를 멈추게 하면 안 되기 때문입니다.
"""

from __future__ import annotations

import re

import requests

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def find_cve_ids(text: str, limit: int = 3) -> list[str]:
    """텍스트에서 CVE 식별자를 중복 없이 추출합니다."""
    seen: list[str] = []
    for match in CVE_PATTERN.findall(text or ""):
        cve = match.upper()
        if cve not in seen:
            seen.append(cve)
        if len(seen) >= limit:
            break
    return seen


def tavily_search(query: str, api_key: str, max_results: int = 4) -> tuple[str, list[dict]]:
    """Tavily 로 웹을 검색해 (요약 텍스트, 출처 목록) 을 돌려줍니다."""
    from langchain_community.tools.tavily_search import TavilySearchResults

    try:
        tool = TavilySearchResults(max_results=max_results, tavily_api_key=api_key)
        results = tool.invoke({"query": query})
    except Exception as exc:
        return f"[웹 검색 실패] {type(exc).__name__}: {exc}", []

    if not isinstance(results, list) or not results:
        return "[웹 검색 결과 없음]", []

    blocks, citations = [], []
    for item in results:
        if not isinstance(item, dict):
            blocks.append(str(item))
            continue
        title = item.get("title") or "(제목 없음)"
        url = item.get("url") or ""
        content = (item.get("content") or "").strip()
        blocks.append(f"### {title}\n{url}\n{content}")
        citations.append({"kind": "web", "title": title, "url": url})

    return "\n\n".join(blocks), citations


def nvd_lookup(cve_ids: list[str], timeout: int = 8) -> tuple[str, list[dict]]:
    """NVD REST API 로 CVE 상세를 조회합니다 (인증 불필요).

    무인증 호출은 30초당 5회 제한이 있어 조회 수를 3건으로 묶고,
    실패해도 앞 단계에서 모은 정보로 답변이 이어지도록 합니다.
    """
    blocks, citations = [], []

    for cve in cve_ids:
        try:
            resp = requests.get(
                NVD_ENDPOINT,
                params={"cveId": cve},
                timeout=timeout,
                headers={"User-Agent": "PromptShield/1.0"},
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities") or []
        except Exception as exc:
            blocks.append(f"### {cve}\n[조회 실패] {type(exc).__name__}: {exc}")
            continue

        if not vulns:
            blocks.append(f"### {cve}\nNVD 에 등록된 정보가 없습니다.")
            continue

        item = vulns[0].get("cve", {})
        desc = next(
            (d.get("value", "") for d in item.get("descriptions", [])
             if d.get("lang") == "en"),
            "",
        )

        severity, score = "N/A", "N/A"
        metrics = item.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                cvss = entries[0].get("cvssData", {})
                severity = cvss.get("baseSeverity") or entries[0].get("baseSeverity", "N/A")
                score = cvss.get("baseScore", "N/A")
                break

        url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        blocks.append(
            f"### {cve}\n"
            f"- CVSS: {score} ({severity})\n"
            f"- 공개일: {item.get('published', 'N/A')[:10]}\n"
            f"- 설명: {desc}"
        )
        citations.append({"kind": "nvd", "title": f"{cve} (CVSS {score})", "url": url})

    return "\n\n".join(blocks) if blocks else "[NVD 조회 결과 없음]", citations
