"""LLM 생성 코드 실행 샌드박스 검증 (LLM 호출 없음)

앱을 공개 배포하므로 프롬프트 인젝션이 곧 임의 코드 실행이 되지 않아야 합니다.

    python -m tests.test_sandbox
"""

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from utils import run_code  # noqa: E402

DF = pd.DataFrame({
    "tenant": ["a", "b", "a"],
    "action": ["blocked", "allowed", "flagged"],
    "injection_label": [1, 0, 1],
    "detector_score": [0.9, 0.1, 0.5],
    "latency_ms": [100, 200, 300],
    "timestamp": ["2026-08-01", "2026-08-02", "2026-08-03"],
})

# 반드시 차단되어야 하는 코드
MUST_BLOCK = [
    ("파일 읽기",          "print(open('/etc/passwd').read())"),
    ("os 모듈",           "import os\nprint(os.listdir('/'))"),
    ("subprocess",       "import subprocess\nprint(subprocess.run(['ls']))"),
    ("__import__ 우회",    "print(__import__('os').getcwd())"),
    ("builtins 접근",      "print(__builtins__)"),
    ("클래스 탈출",         "print(().__class__.__bases__[0].__subclasses__())"),
    ("eval",             "print(eval('1+1'))"),
    ("네트워크",            "import requests\nprint(requests.get('http://x'))"),
    ("pd 로 .env 유출",    "print(pd.read_csv('.env', sep='=', header=None))"),
    ("pd 로 환경변수 유출",  "print(pd.read_csv('/proc/self/environ', header=None))"),
    ("pd 파일 쓰기",       "df.to_csv('/tmp/leak.csv')\nprint('x')"),
    ("pd.io 우회",        "print(pd.io.common.get_handle('.env','r'))"),
    ("numpy 파일 I/O",    "import numpy as np\nprint(np.load('x.npy'))"),
    ("임의 경로 savefig",   "import matplotlib.pyplot as plt\nplt.savefig('/tmp/pwn.png')"),
    ("허용목록 밖 import",  "import pathlib\nprint(pathlib.Path('/'))"),
    ("pickle",           "print(pd.read_pickle('/tmp/x'))"),
    # --- 아래는 문자열 블록리스트 시절 실제로 뚫렸던 경로 ---
    # pd 라는 살아있는 모듈 객체를 타고 진짜 os 모듈에 도달했다.
    # 소스에 'os.' 라는 문자열이 없어 블록리스트가 못 잡았다.
    ("★ pd._libs 경유 RCE",  "o = pd._libs.pandas.compat.os\no.system('echo pwned')"),
    ("★ pd._libs 환경변수",   "o = pd._libs.pandas.compat.os\nprint(o.environ.get('OPENAI_API_KEY'))"),
    ("★ pd.compat.os",     "print(pd.compat.os.getcwd())"),
    ("★ os.open 파일읽기",   "o = pd._libs.pandas.compat.os\nfd = o.open ('.env', 0)\nprint(o.read(fd, 500))"),
    # pandas 의 buf= 인자를 통한 임의 경로 파일 쓰기
    ("★ to_string(buf=)",  "df.head(1).to_string(buf='/tmp/ps_t1')\nprint('w')"),
    ("★ style.to_html",    "df.head(1).style.to_html('/tmp/ps_t2')\nprint('w')"),
    # 표현식 평가기
    ("★ df.query",         "print(df.query('detector_score > 0.9').shape)"),
    ("★ df.eval",          "print(df.eval('detector_score * 2'))"),
    # 자원 고갈
    ("★ 무한 루프",          "while True:\n    pass"),
    ("★ class 정의 탈출",     "class X:\n    pass\nprint(X)"),
    # format 문자열은 속성 접근을 문자열 리터럴 안에 숨겨 AST 를 통과한다.
    ("★ format 클래스 walk",  "print('{0.__class__.__bases__}'.format(()))"),
    ("★ format 모듈 dict",   "print('{0.__dict__}'.format(pd.util))"),
    ("★ format_map",       "print('{a.__class__}'.format_map({'a': 1}))"),
    ("★ 변수 경유 format",     "s = '{0.__class__}'\nprint(s.format(1))"),
    # 아래는 밑줄 규칙만 있던 시절 아키텍트 검증에서 실제로 뚫린 경로다.
    # numpy/matplotlib 은 밑줄 없는 공개 속성으로 하위 모듈을 노출한다.
    ("★ np DataSource 파일읽기", "print(np.lib.npyio.DataSource('.').open('.env').read())"),
    ("★ canvas.print_png",  "plt.plot([1, 2])\nplt.gcf().canvas.print_png('/tmp/x.png')"),
    ("★ canvas.print_figure","plt.plot([1])\nplt.gcf().canvas.print_figure('/tmp/x.pdf')"),
    ("★ np.ctypeslib 로더",  "print(np.ctypeslib.load_library)"),
    ("★ matplotlib.cbook",  "print(plt.cbook)"),
    ("★ get_configdir",     "print(plt.get_configdir())"),
    ("★ import 문",          "import os\nprint(os.getcwd())"),
]

# 반드시 동작해야 하는 정상 분석 코드
MUST_PASS = [
    ("groupby 집계",   "print(df.groupby('tenant')['detector_score'].mean())"),
    ("불리언 필터",     "print(df[df['action'] == 'blocked'].shape[0])"),
    ("미탐 계산",       "print(((df.injection_label == 1) & (df.action == 'allowed')).sum())"),
    ("crosstab",      "print(pd.crosstab(df.injection_label, df.action))"),
    ("to_datetime",   "print(pd.to_datetime(df['timestamp']).dt.date.min())"),
    ("value_counts",  "print(df['action'].value_counts())"),
    ("numpy 통계",     "print(np.mean(df['latency_ms']))"),
    ("pivot_table",   "print(df.pivot_table(index='tenant', values='latency_ms', aggfunc='mean'))"),
    ("for 루프",       "for t in sorted(df.tenant.unique()):\n    print(t, (df.tenant == t).sum())"),
    ("apply/lambda",  "print(df['detector_score'].apply(lambda x: round(x, 1)).value_counts().head(2))"),
    ("describe",      "print(df['detector_score'].describe())"),
    ("f-string 라벨",   "t = 'a'\nprint(f'{t}: {(df.tenant == t).sum()}건')"),
    ("문자열 연결 퍼센트",  "print('차단률: ' + str(round(df.action.eq('blocked').mean() * 100, 1)) + '%')"),
]


def main() -> int:
    failures = 0

    print("=== 차단되어야 하는 코드 ===")
    for name, code in MUST_BLOCK:
        out, ok = run_code(
            code, timeout=6, extra_attrs=set(DF.columns),
            df=DF.copy(), pd=pd, np=np, plt=plt,
        )
        blocked = not ok
        failures += not blocked
        print(f"[{'PASS' if blocked else 'FAIL'}] {name:20} {out[:60]}")

    print("\n=== 동작해야 하는 코드 ===")
    for name, code in MUST_PASS:
        out, ok = run_code(
            code, timeout=6, extra_attrs=set(DF.columns),
            df=DF.copy(), pd=pd, np=np, plt=plt,
        )
        failures += not ok
        print(f"[{'PASS' if ok else 'FAIL'}] {name:20} {out[:50].replace(chr(10), ' ')}")

    total = len(MUST_BLOCK) + len(MUST_PASS)
    print(f"\n{total - failures}/{total} 통과")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
