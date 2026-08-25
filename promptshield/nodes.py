"""PromptShield 노드 구현 (11개)

모든 노드는 자기가 바꾼 키만 담은 dict 를 반환합니다.
LangGraph 가 부분 dict 를 기존 State 에 병합하므로,
앞 노드가 계산한 risk / citations 가 보존됩니다.
"""

from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
from langchain_community.vectorstores import FAISS
from langchain_core.output_parsers import JsonOutputParser, StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from utils import change_plot_to_save, check_code, python_code_parser, run_code

from . import prompts
from .schema import ROUTES, State, risk_level
from .tools import find_cve_ids, nvd_lookup, tavily_search

DATA_DESCRIPTION = "LLM API 게이트웨이 접근 로그 (프롬프트 공격 탐지 결과 포함)"


class PromptShield:
    """그래프의 모든 노드가 공유하는 리소스와 노드 함수를 담습니다."""

    def __init__(
        self,
        openai_api_key: str,
        tavily_api_key: str | None,
        data_dir: Path,
        plot_path: Path,
    ) -> None:
        self.llm = ChatOpenAI(model="gpt-4.1-mini", api_key=openai_api_key)
        # 라우팅·채점·검증은 흔들리면 안 되므로 temperature 를 0 으로 고정합니다.
        self.strict_llm = ChatOpenAI(
            model="gpt-4.1-mini", api_key=openai_api_key, temperature=0
        )
        self.tavily_api_key = tavily_api_key
        self.plot_path = plot_path

        self.df = pd.read_csv(data_dir / "llm_gateway_logs.csv")
        self.columns = ", ".join(self.df.columns)
        self.schema_hint = self._build_schema_hint(self.df)

        embeddings = OpenAIEmbeddings(
            model="text-embedding-3-small", api_key=openai_api_key
        )
        self.vectorstore = FAISS.load_local(
            str(data_dir / "faiss_index"),
            embeddings=embeddings,
            allow_dangerous_deserialization=True,
        )
        self.retriever = self.vectorstore.as_retriever(search_kwargs={"k": 4})

    @staticmethod
    def _build_schema_hint(df: pd.DataFrame, max_values: int = 12) -> str:
        """열 이름·타입과 함께 **실제 범주값**을 프롬프트에 넣기 위한 요약.

        열 목록만 주면 LLM 이 값을 추측해 `action == 'block'` (실제값은 'blocked')
        같은 코드를 만들어 조용히 빈 결과를 냅니다. 실제 값을 알려주면 사라지는
        오류라서, 스키마 힌트를 자동 생성해 프롬프트에 싣습니다.
        """
        lines = []
        for col in df.columns:
            series = df[col]
            dtype = str(series.dtype)
            nunique = series.nunique(dropna=True)
            # pandas 3.x 는 문자열 dtype 이 object 가 아니라 str 이므로 둘 다 받는다.
            is_text = series.dtype == object or pd.api.types.is_string_dtype(series)
            if is_text and nunique <= max_values:
                values = ", ".join(repr(v) for v in sorted(series.dropna().unique()))
                lines.append(f"- {col} ({dtype}): 가능한 값 = {values}")
            elif pd.api.types.is_numeric_dtype(series):
                lines.append(
                    f"- {col} ({dtype}): 범위 {series.min()} ~ {series.max()}"
                )
            else:
                lines.append(f"- {col} ({dtype}): 고유값 {nunique}개")
        return "\n".join(lines)

    # -- 공통 헬퍼 -----------------------------------------------------------
    @staticmethod
    def _note(state: State, text: str) -> list:
        return list(state.get("notes") or []) + [text]

    @staticmethod
    def _cite(state: State, new: list[dict]) -> list:
        return list(state.get("citations") or []) + new

    def _chain(self, system: str, human: str, parser=None, strict: bool = False):
        prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])
        llm = self.strict_llm if strict else self.llm
        return prompt | llm | (parser or StrOutputParser())

    # -- 1. triage -----------------------------------------------------------
    def triage(self, state: State) -> dict:
        """질문 유형을 판정해 6개 경로 중 하나를 고릅니다."""
        chain = self._chain(
            prompts.TRIAGE, "{question}", JsonOutputParser(), strict=True
        )
        try:
            result = chain.invoke({"question": state["question"]})
            route = str(result.get("route", "")).strip().lower()
        except Exception:
            route = ""

        # 화이트리스트 밖의 값이 나오면 조건부 엣지에서 KeyError 가 나므로 방어합니다.
        if route not in ROUTES:
            route = "plain"

        return {"route": route, "notes": self._note(state, f"질문 유형: {route}")}

    # -- 2. payload_analyst --------------------------------------------------
    def payload_analyst(self, state: State) -> dict:
        """입력이 프롬프트 공격인지 판정하고 정량 위험점수를 매깁니다."""
        chain = self._chain(
            prompts.PAYLOAD_ANALYST,
            "판정할 입력:\n{question}",
            JsonOutputParser(),
            strict=True,
        )
        try:
            result = chain.invoke({"question": state["question"]})
            score = int(result.get("score", 0))
            technique = str(result.get("technique", "NONE"))
            rationale = str(result.get("rationale", ""))
        except Exception as exc:
            score, technique = 50, "NONE"
            rationale = f"자동 판정 실패({type(exc).__name__}) — 보수적으로 중간 등급 처리"

        score = max(0, min(100, score))
        risk = {
            "score": score,
            "level": risk_level(score),
            "technique": technique,
            "rationale": rationale,
        }
        return {
            "risk": risk,
            "notes": self._note(state, f"위험 판정: {score}점 ({risk['level']}) / {technique}"),
        }

    # -- 3. log_analyst ------------------------------------------------------
    def log_analyst(self, state: State) -> dict:
        """pandas 코드를 생성·실행해 로그를 조회합니다 (실패 시 재시도 대상)."""
        retry = int(state.get("code_retry") or 0)
        system = prompts.LOG_ANALYST.format(
            description=DATA_DESCRIPTION, schema=self.schema_hint
        )

        if retry == 0:
            chain = self._chain(system, "{question}") | python_code_parser
            code = chain.invoke({"question": state["question"]})
        else:
            # 재시도에서는 실패한 코드와 오류를 함께 넘겨 원인을 고치게 합니다.
            human = prompts.LOG_ANALYST_RETRY + "\n\n원래 질문: {question}"
            chain = self._chain(system, human) | python_code_parser
            code = chain.invoke({
                "question": state["question"],
                "code": state.get("code", ""),
                "error": state.get("data", ""),
            })

        output, ok = run_code(code, require_output=True, df=self.df.copy(), pd=pd)
        note = "로그 조회 성공" if ok else f"로그 조회 실패 (시도 {retry + 1})"
        return {
            "code": code,
            "data": output,
            "code_retry": retry + 1,
            "notes": self._note(state, note),
            "citations": self._cite(
                state, [{"kind": "csv", "title": "llm_gateway_logs.csv", "url": ""}]
            ) if ok else list(state.get("citations") or []),
        }

    # -- 4. atlas_rag --------------------------------------------------------
    def atlas_rag(self, state: State) -> dict:
        """MITRE ATLAS / NIST 문서를 벡터 검색합니다."""
        query = state["question"]
        risk = state.get("risk") or {}
        # 위험 판정을 거쳐 넘어온 경우 기법 ID 를 쿼리에 실어 검색 정확도를 올립니다.
        if risk.get("technique") and risk["technique"] != "NONE":
            query = f"{risk['technique']} {query}"

        docs = self.retriever.invoke(query)
        context = "\n\n".join(d.page_content for d in docs)
        sources = []
        for d in docs:
            name = d.metadata.get("source", "knowledge")
            if name not in [s["title"] for s in sources]:
                sources.append({"kind": "doc", "title": name, "url": ""})

        return {
            "context": context,
            "citations": self._cite(state, sources),
            "notes": self._note(state, f"지식 검색: {len(docs)}개 청크"),
        }

    # -- 5. grade_docs -------------------------------------------------------
    def grade_docs(self, state: State) -> dict:
        """검색 결과가 질문에 답하기 충분한지 채점합니다 (CRAG)."""
        chain = self._chain(
            prompts.GRADE_DOCS,
            "질문: {question}\n\n검색된 문서:\n{context}",
            JsonOutputParser(),
            strict=True,
        )
        try:
            result = chain.invoke({
                "question": state["question"],
                "context": (state.get("context") or "")[:6000],
            })
            grade = str(result.get("grade", "")).strip().lower()
            reason = str(result.get("reason", ""))
        except Exception:
            grade, reason = "sufficient", "채점 실패 — 검색 결과를 그대로 사용"

        if grade not in ("sufficient", "insufficient"):
            grade = "sufficient"

        return {
            "verdict": grade,
            "notes": self._note(state, f"검색 품질: {grade} ({reason})"),
        }

    # -- 6. threat_intel (웹 API) -------------------------------------------
    def threat_intel(self, state: State) -> dict:
        """Tavily 로 최신 위협 인텔리전스를 검색합니다."""
        if not self.tavily_api_key:
            return {
                "web_results": "[Tavily API 키가 설정되지 않아 웹 검색을 건너뜁니다]",
                "notes": self._note(state, "웹 검색 건너뜀 (키 없음)"),
            }

        risk = state.get("risk") or {}
        query = state["question"]
        if risk.get("technique") and risk["technique"] != "NONE":
            query = f"{query} {risk['technique']} LLM prompt injection mitigation"

        text, sources = tavily_search(query, self.tavily_api_key)
        return {
            "web_results": text,
            "citations": self._cite(state, sources),
            "notes": self._note(state, f"웹 검색: 출처 {len(sources)}건"),
        }

    # -- 7. cve_lookup (웹 API) ---------------------------------------------
    def cve_lookup(self, state: State) -> dict:
        """웹 검색 결과에서 발견된 CVE 를 NVD 에서 상세 조회합니다."""
        haystack = f"{state.get('web_results','')}\n{state.get('question','')}"
        cve_ids = find_cve_ids(haystack)
        text, sources = nvd_lookup(cve_ids)

        merged = (state.get("web_results") or "") + "\n\n## NVD 상세\n" + text
        return {
            "web_results": merged,
            "citations": self._cite(state, sources),
            "notes": self._note(state, f"NVD 조회: {', '.join(cve_ids)}"),
        }

    # -- 8. visualizer -------------------------------------------------------
    def visualizer(self, state: State) -> dict:
        """matplotlib 코드를 생성·실행해 차트를 만듭니다."""
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        system = prompts.VISUALIZER.format(
            description=DATA_DESCRIPTION, schema=self.schema_hint
        )
        chain = self._chain(system, "{question}") | python_code_parser
        raw_code = chain.invoke({"question": state["question"]})

        # LLM 코드를 먼저 검사한 뒤, 저장 구문은 우리가 통제해서 붙인다.
        # (순서를 바꾸면 우리가 붙인 savefig 가 검사에 걸린다)
        violation = check_code(raw_code)
        if violation:
            return {
                "code": raw_code,
                "data": f"차트 생성을 거부했습니다. {violation}",
                "plot": "",
                "notes": self._note(state, f"차트 생성 거부: {violation}"),
            }

        code = change_plot_to_save(raw_code, str(self.plot_path))
        self.plot_path.unlink(missing_ok=True)
        # 차트 코드는 stdout 이 비는 게 정상이므로 출력 유무로 성패를 가르지 않는다.
        output, ok = run_code(
            code, require_output=False, pre_checked=True,
            df=self.df.copy(), pd=pd, plt=plt,
        )
        made = ok and self.plot_path.exists()

        if made:
            data = (
                f"차트를 생성해 {self.plot_path.name} 로 저장했습니다.\n"
                f"차트를 그리는 데 사용한 코드:\n```python\n{code}\n```"
            )
        else:
            data = f"차트 생성에 실패했습니다.\n{output}"

        return {
            "code": code,
            "data": data,
            "plot": str(self.plot_path) if made else "",
            "notes": self._note(state, "차트 생성 성공" if made else f"차트 생성 실패: {output[:120]}"),
            "citations": self._cite(
                state, [{"kind": "csv", "title": "llm_gateway_logs.csv", "url": ""}]
            ),
        }

    # -- 9. playbook_writer --------------------------------------------------
    @staticmethod
    def _collect_evidence(state: State) -> str:
        """수집된 근거를 라벨이 붙은 하나의 문서로 모읍니다.

        playbook_writer 와 verifier 가 **같은 근거**를 보게 하는 것이 핵심입니다.
        예전에는 verifier 에게 조회 결과 문자열만 넘겼는데,
        "탐지기가 놓친 공격은?" 같은 질문의 결과가 `9` 한 글자라
        검증관이 그 숫자가 무엇인지 알 수 없어 정답을 탈락시켰습니다.
        그래서 실행한 코드까지 함께 넘겨 숫자의 맥락이 드러나게 합니다.
        """
        risk = state.get("risk") or {}
        parts = []

        if risk:
            parts.append(
                f"## 위험 판정\n- 점수: {risk.get('score')} ({risk.get('level')})\n"
                f"- ATLAS 기법: {risk.get('technique')}\n- 근거: {risk.get('rationale')}"
            )

        if state.get("plot"):
            parts.append(f"## 차트 생성 결과\n{(state.get('data') or '')[:2000]}")
        elif state.get("data"):
            block = [f"## 게이트웨이 로그 조회 결과 (질문: {state.get('question','')})"]
            if state.get("code"):
                block.append(
                    "실행한 조회 코드:\n```python\n"
                    f"{state['code'].strip()[:1200]}\n```"
                )
            block.append(f"위 코드의 실행 출력:\n```\n{state['data'][:3000]}\n```")
            block.append(
                "→ 이 출력은 실제 로그 데이터(llm_gateway_logs.csv)를 코드로 집계한 "
                "결과이므로, 질문에 대한 근거로 그대로 사용할 수 있습니다."
            )
            parts.append("\n\n".join(block))

        if state.get("context"):
            parts.append(f"## 지식베이스 검색\n{state['context'][:6000]}")
        if state.get("web_results"):
            parts.append(f"## 웹 위협 인텔\n{state['web_results'][:5000]}")

        return "\n\n".join(parts) if parts else "(수집된 근거 없음)"

    def playbook_writer(self, state: State) -> dict:
        """모아온 근거를 종합해 최종 답변(대응 플레이북)을 씁니다."""
        evidence = self._collect_evidence(state)
        rewrite = int(state.get("rewrite_count") or 0)
        human = "질문: {question}\n\n수집된 근거:\n{evidence}"
        if rewrite > 0:
            human += (
                "\n\n주의: 직전 답변이 근거 충실도 검증에서 탈락했습니다. "
                "근거에서 확인되지 않는 단정만 덜어내고, **근거에서 확인되는 사실은 "
                "그대로 유지**하세요. 근거에 답이 있는데도 '알 수 없다'고 쓰면 안 됩니다."
            )

        chain = self._chain(prompts.PLAYBOOK_WRITER, human)
        generation = chain.invoke({
            "question": state["question"],
            "evidence": evidence,
        })

        return {
            "generation": generation,
            "rewrite_count": rewrite,
            "notes": self._note(state, "답변 작성" + (" (재작성)" if rewrite else "")),
        }

    # -- 10. verifier --------------------------------------------------------
    def verifier(self, state: State) -> dict:
        """답변이 근거에 실제로 기반하는지 검증합니다 (환각 차단)."""
        # playbook_writer 와 동일한 근거를 봐야 판정이 어긋나지 않습니다.
        evidence = self._collect_evidence(state)

        chain = self._chain(
            prompts.VERIFIER,
            "근거:\n{evidence}\n\n작성된 답변:\n{generation}",
            JsonOutputParser(),
            strict=True,
        )
        try:
            result = chain.invoke({
                "evidence": evidence,
                "generation": state.get("generation", ""),
            })
            verdict = str(result.get("verdict", "")).strip().lower()
            reason = str(result.get("reason", ""))
        except Exception:
            verdict, reason = "pass", "검증 실패 — 통과 처리"

        if verdict not in ("pass", "fail"):
            verdict = "pass"

        rewrite = int(state.get("rewrite_count") or 0)
        return {
            "verdict": verdict,
            # fail 이면 재작성 카운터를 올려 무한 루프를 막습니다.
            "rewrite_count": rewrite + 1 if verdict == "fail" else rewrite,
            "notes": self._note(state, f"근거 검증: {verdict} ({reason})"),
        }

    # -- 11. plain_answer ----------------------------------------------------
    def plain_answer(self, state: State) -> dict:
        """보안과 무관한 질문, 또는 로그 조회가 끝내 실패한 경우의 답변."""
        failed = state.get("route") == "log" and int(state.get("code_retry") or 0) > 0
        if failed:
            generation = (
                "요청하신 로그 조회를 여러 번 시도했지만 실패했습니다.\n\n"
                f"마지막 오류:\n```\n{state.get('data','')[:500]}\n```\n\n"
                "질문을 조금 더 구체적으로 다시 말씀해 주세요. "
                "예: `테넌트별 차단률을 알려줘`"
            )
        else:
            chain = self._chain(prompts.PLAIN_ANSWER, "{question}")
            generation = chain.invoke({"question": state["question"]})

        return {
            "generation": generation,
            "notes": self._note(state, "일반 답변"),
        }
