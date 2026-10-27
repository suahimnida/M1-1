"""
CISA KEV(실제 악용된 취약점 목록) 시계열 트렌드 분석
실행: python analysis.py
  - data/ 폴더의 CSV를 읽어서
  - images/ 폴더에 그래프 4개를 저장하고
  - 콘솔에 리포트에 쓸 수치를 출력한다.
"""
import collections
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

# ── 0. 설정 ──────────────────────────────────────────────
DATA = Path("data/known_exploited_vulnerabilities.csv")
IMG = Path("images")
IMG.mkdir(exist_ok=True)

# 한글 폰트: 윈도우(맑은 고딕) → 맥(AppleGothic) → 리눅스(나눔/Noto) 순으로 시도
import logging
import matplotlib.font_manager as fm
logging.getLogger("matplotlib.font_manager").setLevel(logging.ERROR)  # 폰트 탐색 로그 숨김
for p in ["/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
          "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"]:
    if Path(p).exists():
        fm.fontManager.addfont(p)
plt.rcParams["font.family"] = ["Malgun Gothic", "AppleGothic", "NanumGothic",
                               "Noto Sans CJK JP", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

START, END = "2023-01-01", "2025-12-31"  # 분석 기간: 완전한 3개 연도 (선정 이유는 REPORT.md 참고)

# 네트워크 경계 장비(VPN·방화벽·라우터 등) 제조사 목록 - 분류 기준은 REPORT.md 부록
EDGE_VENDORS = ["Cisco", "Fortinet", "Ivanti", "Palo Alto Networks", "Citrix", "SonicWall",
                "Juniper", "F5", "Zyxel", "Check Point", "Array Networks", "Sophos",
                "WatchGuard", "Pulse Secure", "D-Link", "TP-Link", "NETGEAR", "DrayTek"]

# 위 제조사의 제품 중 경계 장비가 아닌 것 (검증 과정에서 발견해 제외)
# 엔드포인트·모바일 관리, 통화 서버, 라이선스 도구, 세션 녹화, 파일 공유, 카메라·NAS·영상저장장치,
# 엔드포인트 보안 관리 서버, 방화벽 설정 마이그레이션 도구
NON_EDGE_PRODUCTS = ["Endpoint Manager", "EPMM", "Unified Communications", "Smart Licensing",
                     "Session Recording", "Content Collaboration", "DCS-", "NAS", "DNR-",
                     "FortiClient EMS", "Expedition"]

# ── 1. 데이터 불러오기 & 기본 정보 ─────────────────────────
df = pd.read_csv(DATA, parse_dates=["dateAdded"])
print("== 기본 정보 ==")
print("전체 행 수:", len(df))
print("기간:", df.dateAdded.min().date(), "~", df.dateAdded.max().date())
print("컬럼:", list(df.columns))
na = df.isna().sum()
print("결측치 개수:\n", na[na > 0])
print("중복 cveID:", df.cveID.duplicated().sum())

# ── 2. 정제 ───────────────────────────────────────────────
# (1) CVE 번호의 연도 = 취약점이 번호를 받은 해 → KEV 등재 시점의 '연식' 계산
df["cve_year"] = df.cveID.str.extract(r"CVE-(\d{4})")[0].astype(int)
df["year"] = df.dateAdded.dt.year
df["age"] = df.year - df.cve_year

# (2) 이상치 확인: 하루 추가 건수 상위
daily = df.groupby("dateAdded").size().sort_values(ascending=False)
print("\n== 하루 추가 건수 상위 5일 (이상치 후보) ==\n", daily.head())

# (3) 연도별 '1년 이내 신규 취약점' 비율 → 초기 일괄 등록 구간 판별
# 2026년은 아직 끝나지 않은 해라 이 비교에서도 제외
young = df[df.year <= 2025].groupby("year").age.apply(lambda s: (s <= 1).mean())
print("\n== 연도별 신규(등재 시 1년 이내) 비율 ==\n", young.round(2))

# (4) 분석 구간만 남기기
d = df[(df.dateAdded >= START) & (df.dateAdded <= END)].copy()
print(f"\n분석 대상: {len(d)}건 ({START} ~ {END})")

# ── 그래프 0: 데이터 품질 근거 (연도별 신규 취약점 비율) ──────
fig, ax = plt.subplots(figsize=(8, 4))
colors = ["#bbbbbb" if y < 2023 else "#3b7dd8" for y in young.index]
labels = [str(y) for y in young.index]
ax.bar(labels, young.values * 100, color=colors)
ax.set_title("연도별 '등재 시점에 1년 이내였던 취약점' 비율 (회색 = 분석 제외)")
ax.set_ylabel("%")
ax.set_ylim(0, 100)
for x, v in zip(labels, young.values * 100):
    ax.text(x, v + 2, f"{v:.0f}%", ha="center")
plt.tight_layout()
plt.savefig(IMG / "00_data_quality_age.png", dpi=150)
plt.close()

# ── 3. 분석 ① 주별 추가 건수 + 이동평균 ────────────────────
# 월 단위로는 45개 포인트뿐이라(기준 100개 미만) 주 단위로 집계
weekly = d.set_index("dateAdded").resample("W-MON", label="left", closed="left").size()
full_range = pd.date_range(weekly.index.min(), weekly.index.max(), freq="W-MON")
weekly = weekly.reindex(full_range, fill_value=0)  # 추가가 없던 주는 결측이 아니라 '0건'
weekly = weekly[weekly.index + pd.Timedelta(days=6) <= END]  # 7일이 다 차지 않은 마지막 주 제외
ma12 = weekly.rolling(12).mean()  # 12주(약 3개월) 이동평균
print("\n== 주별 데이터 포인트 수:", len(weekly), "==")
print("추가 0건인 주:", int((weekly == 0).sum()))

fig, ax = plt.subplots(figsize=(11, 4.5))
ax.bar(weekly.index, weekly.values, width=5, color="#c9d6ea", label="주별 추가 건수")
ax.plot(ma12.index, ma12.values, color="#1f4e99", lw=2.2, label="12주 이동평균")
ax.set_title("CISA KEV 주별 추가 건수 (2023.01 ~ 2025.12)")
ax.set_ylabel("건수")
ax.legend()
plt.tight_layout()
plt.savefig(IMG / "01_weekly_trend.png", dpi=150)
plt.close()

# 연도별 구간 통계 + 전년 대비 변화율
# 3개 연도 모두 1~12월이 다 있으므로 연간 전체 건수로 바로 비교
full = d.groupby("year").size()
wk_stats = weekly.groupby(weekly.index.year).agg(["mean", "std", "max"]).round(2)
print("\n== 연도별 전체 건수 ==\n", full)
print("== 전년 대비 변화율(%) ==\n", (full.pct_change() * 100).round(1))
print("== 연도별 주간 통계(평균/표준편차/최대) ==\n", wk_stats)

# ── 4. 분석 ② 네트워크 경계 장비 비중 (분기별) ───────────────
d["edge_vendor"] = d.vendorProject.isin(EDGE_VENDORS)  # 1단계: 제조사 기준
non_edge = d["product"].str.contains("|".join(NON_EDGE_PRODUCTS), regex=True)
d["edge"] = d.edge_vendor & ~non_edge                   # 2단계: 경계 장비가 아닌 제품 제외
print("\n== 경계 장비 분류 ==")
print("제조사 기준:", int(d.edge_vendor.sum()), "건 → 비경계 제품 제외 후:", int(d.edge.sum()), "건")
print("제외된 제품:\n", d[d.edge_vendor & non_edge]["product"].value_counts())
print("== 연도별 비중 비교(%): 제조사 기준 vs 보정 후 ==\n",
      pd.DataFrame({"vendor_only": d.groupby("year").edge_vendor.mean() * 100,
                    "corrected": d.groupby("year").edge.mean() * 100}).round(1))
d["quarter"] = d.dateAdded.dt.to_period("Q")
q = d.groupby("quarter").agg(total=("cveID", "size"), edge=("edge", "sum"))
q["share"] = q.edge / q.total * 100
q["share_ma"] = q.share.rolling(4).mean()  # 4분기 이동평균
yearly_edge = d.groupby("year").edge.mean() * 100
print("\n== 분기별 경계 장비 비중 ==\n", q.round(1))
print("== 연도별 경계 장비 비중(%) ==\n", yearly_edge.round(1))
print("== 전년 대비 %p 변화 ==\n", yearly_edge.diff().round(1))
print("== 경계 장비 중 제조사 상위 ==\n", d[d.edge].vendorProject.value_counts().head(6))

fig, ax = plt.subplots(figsize=(11, 4.5))
x = q.index.astype(str)
ax.bar(x, q.share, color="#f2b880", label="분기별 비중")
ax.plot(x, q.share_ma, color="#c0392b", lw=2.2, marker="o", label="4분기 이동평균")
ax.set_title("KEV 중 네트워크 경계 장비(VPN·방화벽 등) 취약점 비중 (제품 기준 보정)")
ax.set_ylabel("%")
ax.legend()
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig(IMG / "02_edge_device_share.png", dpi=150)
plt.close()

# ── 5. 분석 ③ 연도별 상위 취약점 유형(CWE) ────────────────
# CVE 하나에 CWE가 여러 개면 각각 1회씩 집계 (그래서 비율 합이 100%를 넘을 수 있음)
CWE_NAME = {"CWE-78": "OS 명령어 인젝션", "CWE-502": "역직렬화", "CWE-22": "경로 조작",
            "CWE-416": "Use-After-Free", "CWE-787": "범위 밖 쓰기", "CWE-94": "코드 인젝션",
            "CWE-287": "부적절한 인증", "CWE-306": "인증 누락", "CWE-20": "입력 검증 미흡",
            "CWE-77": "명령어 인젝션", "CWE-79": "XSS", "CWE-862": "권한 검사 누락"}
print("\n== 연도별 CWE 비어 있는 비율 ==\n",
      d.groupby("year").cwes.apply(lambda s: s.isna().mean()).round(3))

counts = {}
for y, g in d.groupby("year"):
    counts[y] = collections.Counter(w.strip() for s in g.cwes.dropna() for w in s.split(","))
top = collections.Counter()
for c in counts.values():
    top.update(c)
top_cwes = [w for w, _ in top.most_common(8)]
tab = pd.DataFrame({y: [counts[y].get(w, 0) for w in top_cwes] for y in counts}, index=top_cwes)
share_tab = (tab / d.groupby("year").size() * 100).round(1)  # 그 해 KEV 건수 대비 %
print("\n== 상위 CWE 연도별 건수 ==\n", tab)
print("== 상위 CWE 연도별 비율(%) ==\n", share_tab)

fig, ax = plt.subplots(figsize=(9, 5))
im = ax.imshow(share_tab.values, cmap="Blues", aspect="auto")
ax.set_xticks(range(len(share_tab.columns)),
              [str(c) for c in share_tab.columns])
ax.set_yticks(range(len(top_cwes)), [f"{w} {CWE_NAME.get(w, '')}" for w in top_cwes])
vmax = share_tab.values.max()
for i in range(share_tab.shape[0]):
    for j in range(share_tab.shape[1]):
        v = share_tab.iat[i, j]
        ax.text(j, i, f"{v:.1f}", ha="center", va="center",
                color="white" if v > vmax * 0.6 else "black")
ax.set_title("연도별 상위 취약점 유형 비율 (그 해 KEV 건수 대비 %)")
plt.colorbar(im, ax=ax, shrink=0.8)
plt.tight_layout()
plt.savefig(IMG / "03_cwe_heatmap.png", dpi=150)
plt.close()

print("\n완료: images/ 폴더에 그래프 4개 저장")
