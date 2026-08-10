# MDPI 논문 수정추적 영문·국문본

> 비교 기준: `KCMVP_MDPI_Overleaf_FAST.zip`과 2026-08-11 현재 MDPI 원고이다. 기존 문장은 취소선, 수정 문장은 빨간색으로 표시한다. 한국어 번역은 학술체 `~한다`를 사용한다.

> LaTeX 원고를 직접 수정하기 전 검토하는 문서이다. 그림 파일은 생략하고 캡션을 보존한다. 제3장은 완전성 보장을 위해 최신 영문 원문층, 학술체 국문 번역층, 변경 추적층으로 구분한다.

# MDPI 논문 Front Matter 및 참고문헌 원문

> 기준 파일: `main.tex`, `references_generated.tex` (2026-08-11 현재본)
> 목적: 논문 수정추적 Markdown에 병합하기 위한 무누락 원문이다.
> 보존 원칙: 저자명, 이메일, 연도, 인용 키, LaTeX 명령 및 참고문헌 문구를 원문 그대로 유지한다.

## Journal Metadata

| Field | Original value | 한국어 설명 |
|---|---:|---|
| Document class | `applsci,article,submit,pdftex,moreauthors` | Applied Sciences 투고용 논문 형식을 사용한다. |
| First page | `1` | 시작 쪽은 1쪽으로 설정한다. |
| Volume | `1` | 권은 투고 템플릿의 임시 값 1로 설정한다. |
| Issue | `1` | 호는 투고 템플릿의 임시 값 1로 설정한다. |
| Article number | `0` | 논문 번호는 투고 템플릿의 임시 값 0으로 설정한다. |
| Publication year | `2026` | 출판 연도는 2026년으로 설정한다. |
| Copyright year | `2026` | 저작권 연도는 2026년으로 설정한다. |
| Date received | blank | 접수일은 미정이다. |
| Date revised | blank | 수정일은 미정이다. |
| Date accepted | blank | 게재 승인일은 미정이다. |
| Date published | blank | 출판일은 미정이다. |

## Title

**Original:** AI-Based KCMVP Pre-Certification System: A Hybrid Model of Rule-Based Detection and LLM Semantic Analysis

**한국어 번역:** 인공지능 기반 KCMVP 사전 인증 시스템: 규칙 기반 탐지와 대규모 언어 모델 의미 분석의 하이브리드 모델

## Authors

**Original author line:** Su-Been Cho $^{1}$, Do-Yun Park $^{1}$, Da-Eun Lim $^{1}$, Jae-Hwan Kim $^{1}$, Su-Min Jeong $^{1}$, Yu-Lim Hyoung $^{1}$ and Hwa-Jeong Seo $^{1,}$*

**Author names metadata:** Su-Been Cho, Do-Yun Park, Da-Eun Lim, Jae-Hwan Kim, Su-Min Jeong, Yu-Lim Hyoung and Hwa-Jeong Seo

**한국어 설명:** 저자는 Su-Been Cho, Do-Yun Park, Da-Eun Lim, Jae-Hwan Kim, Su-Min Jeong, Yu-Lim Hyoung 및 Hwa-Jeong Seo로 구성하며, 별표는 교신저자를 나타낸다.

## Affiliation and Contact Information

**Original:** Department of Convergence Security, Hansung University, Seoul 02876, South Korea; chosubin1208@gmail.com (S.-B.C.); rhcp030418@gmail.com (D.-Y.P.); limadaeun@gmail.com (D.-E.L.); jaedol2023@gmail.com (J.-H.K.); jeong9sumin@gmail.com (S.-M.J.); yulim4hyoung@gmail.com (Y.-L.H.); hwajeong84@gmail.com (H.-J.S.)

**한국어 번역:** 대한민국 서울특별시 02876, 한성대학교 융합보안학과; chosubin1208@gmail.com (S.-B.C.); rhcp030418@gmail.com (D.-Y.P.); limadaeun@gmail.com (D.-E.L.); jaedol2023@gmail.com (J.-H.K.); jeong9sumin@gmail.com (S.-M.J.); yulim4hyoung@gmail.com (Y.-L.H.); hwajeong84@gmail.com (H.-J.S.)

## Correspondence

**Original:** Correspondence: hwajeong84@gmail.com (H.-J.S.)

**한국어 번역:** 교신저자: hwajeong84@gmail.com (H.-J.S.)


---

# KCMVP 논문 변경 검토본 — Abstract, Introduction, Background

> 비교 기준: `KCMVP_MDPI_Overleaf_FAST.zip`(2026-08-10 18:48) → `overleaf/` 현재본
> 표기: ~~삭제된 기존 문장~~ / <span style="color:red">추가·대체된 현재 문장</span>
> 이 문서는 검토용이며 LaTeX 원본을 수정하지 않는다. 인용 키와 수치는 원문대로 보존한다.

## Abstract

~~The Korean Cryptographic Module Validation Program (KCMVP) is a national certification system that verifies the security and conformity of cryptographic modules deployed in government and public institutions. The current process typically takes about one and a half years, during which frequent supplement requests and the resulting re-testing cycles substantially raise costs and delay schedules. To address this, we propose an AI-based pre-certification framework that combines rule-based deterministic detection (L1), RAG-based guideline-evidence retrieval (L2), and LLM-based final decision (L3) into a funnel-shaped pipeline that progressively reduces false positives. L1 applies more than 170 YAML inspection rules across four pattern types (missing, regex, semantic, ast) to perform deterministic detection. L2 retrieves and attaches KCMVP guideline evidence to each violation through multi-stage RAG search, and L3 employs Gemini 2.5 Flash-Lite to make context-aware decisions on false-positive candidates. In an initial evaluation on 128 Ground Truth cases derived from the KISA LEA code, the system detected all 128 cases, achieving 100% recall, while L3 correctly removed 9 of 46 FP candidates (19.6%) without inducing any false negatives (FN), confirming the stepwise refinement effect of the funnel structure. A blind verification on a certified commercial cryptographic module (~14.5 KLOC) yielded a low detection frequency of 0.58 cases per 1,000 lines of code, supporting the system's practicality in real environments.~~

<span style="color:red">The Korean Cryptographic Module Validation Program (KCMVP) is a national certification system that verifies cryptographic modules deployed in government and public institutions. Its review and supplementation cycles motivate tools that can identify candidate issues before submission. We propose a framework combining rule-based detection (L1), RAG-based evidence retrieval (L2), and LLM-based re-evaluation (L3). The current repository snapshot encodes 161 YAML assets: 92 code-analysis rules, 65 document rules, and four traceability rules executed separately. A legacy author-constructed evaluation on 128 LEA-based labeled cases reported 128 detections and removal of 9 among 46 author-labeled FP candidates without removing a labeled violation. Because that run predates immutable experiment manifests, these figures are preliminary legacy observations rather than reproducible estimates for the current snapshot. Independent labeling, controlled L2 ablation, and cross-algorithm evaluation are required before broader generalization.</span>

**한국어 번역:** 한국 암호모듈 검증제도(KCMVP)는 정부 및 공공기관에 배치되는 암호모듈을 검증하는 국가 인증제도이다. 검토 및 보완 절차는 제출 전에 잠재적 문제를 식별할 수 있는 도구의 필요성을 제기한다. 본 연구는 규칙 기반 탐지(L1), 검색 증강 생성 기반 증거 검색(L2), 대규모 언어 모델 기반 재평가(L3)를 결합한 프레임워크를 제안한다. 현재 저장소 스냅샷은 코드 분석 규칙 92개, 문서 규칙 65개, 별도로 실행되는 추적성 규칙 4개로 구성된 총 161개의 YAML 자산을 포함한다. LEA 기반 라벨링 사례 128개를 대상으로 저자가 구축한 과거 평가에서는 128개 사례가 모두 탐지되었으며, 라벨링된 위반 사례를 제거하지 않으면서 저자가 오탐으로 라벨링한 후보 46개 중 9개가 제거된 것으로 보고되었다. 그러나 해당 실행은 불변 실험 매니페스트가 도입되기 전에 수행되었으므로, 이 수치는 현재 스냅샷에 대한 재현 가능한 추정치가 아니라 예비적인 과거 관찰 결과에 해당한다. 보다 광범위한 일반화를 주장하기 위해서는 독립 라벨링, 통제된 L2 절제 실험 및 알고리즘 간 평가가 필요하다.

**Keywords:** KCMVP; artificial intelligence; large language model; pre-certification; retrieval-augmented generation; rule-based detection; abstract syntax tree; multi-layer analysis; semantic verification; pre-conformance inspection

**한국어 번역:** KCMVP; 인공지능; 대규모 언어 모델; 사전 인증; 검색 증강 생성; 규칙 기반 탐지; 추상 구문 트리; 다계층 분석; 의미론적 검증; 사전 적합성 검사

## 1. Introduction

The Korean Cryptographic Module Validation Program (KCMVP [nis2025]), administered by the National Intelligence Service (NIS) and the Korea Internet & Security Agency (KISA), is a mandatory statutory certification system for cryptographic modules deployed in the information systems of government and public institutions. Under the Electronic Government Act, all cryptographic modules operated on the national network of administrative agencies and the like must pass KCMVP validation, and this functions as a core pillar that supports the Republic of Korea's national cybersecurity infrastructure.

**한국어 번역:** 국가정보원(NIS)과 한국인터넷진흥원(KISA)이 운영하는 한국 암호모듈 검증제도(KCMVP [nis2025])는 정부 및 공공기관의 정보시스템에 배치되는 암호모듈에 적용되는 법정 의무 인증제도이다. 전자정부법에 따라 행정기관 등의 국가정보통신망에서 운용되는 모든 암호모듈은 KCMVP 검증을 통과해야 하며, 이는 대한민국 국가 사이버보안 기반을 지탱하는 핵심 축으로 기능한다.

The KCMVP validation procedure broadly consists of four stages: validation application, document review, technical review (main examination), and final deliberation/certification [nis2025].

**한국어 번역:** KCMVP 검증 절차는 크게 검증 신청, 문서 검토, 기술 검토(본심사), 최종 심의 및 인증의 네 단계로 구성된다 [nis2025].

In particular, at the technical review stage, the validator analyzes the source code and rigorously inspects the correctness of the cryptographic algorithm implementation, compliance with secure coding practices, and the consistency between the source code and the submitted documents.

**한국어 번역:** 특히 기술 검토 단계에서 검증자는 소스 코드를 분석하고 암호 알고리즘 구현의 정확성, 안전한 코딩 관행의 준수 여부 및 소스 코드와 제출 문서 간 일관성을 엄격하게 검사한다.

~~The main bottleneck in the current validation process occurs at the Supplement Requests stage. When a defect is found during the validation process, the applicant organization must correct the issue, re-perform the relevant tests, and resubmit. Each time this supplement cycle is repeated, additional delays of several weeks to several months arise, and when remediation work is performed through external consulting, a substantial cost burden is incurred. Despite such clear limitations, no automated pre-certification tool currently exists that would allow developers to autonomously inspect their source code and documents against KCMVP requirements before official submission.~~

<span style="color:red">One practical source of delay is the supplement-request cycle. When a defect is found, the applicant must correct the issue, repeat the relevant tests, and resubmit. Repeated cycles can delay completion and add remediation cost. To our knowledge, publicly documented tools do not jointly inspect source code, submitted documents, and their traceability against KCMVP-specific requirements before official submission.</span>

**한국어 번역:** 실무적 지연을 유발하는 요인 중 하나는 보완 요청 주기이다. 결함이 발견되면 신청자는 해당 문제를 수정하고 관련 시험을 반복한 후 다시 제출해야 한다. 이러한 주기가 반복되면 완료가 지연되고 보완 비용이 증가할 수 있다. 저자들이 조사한 바에 따르면, 공식 제출 전에 소스 코드, 제출 문서 및 이들 간 추적성을 KCMVP 고유 요구사항에 따라 통합적으로 검사하는 공개 문서화된 도구는 존재하지 않는다.

~~To fill this gap, in this study we propose a hybrid pre-certification tool -- combining rule-based static inspection with Retrieval-Augmented Generation (RAG) and Large Language Models -- that automatically scans the source code and submitted documents for potential KCMVP violations before the official review begins, thereby reducing the frequency and severity of supplement requests. Note, however, that the system proposed in this paper is a pre-certification auxiliary tool and a prototype, and we explicitly emphasize that it does not replace the official KCMVP validation process of national agencies.~~

<span style="color:red">To fill this gap, in this study we propose a hybrid pre-certification tool -- combining rule-based static inspection with Retrieval-Augmented Generation (RAG) and Large Language Models -- intended to help identify potential KCMVP issues before official review. The system is an auxiliary prototype and does not replace official validation; this study does not measure a reduction in actual supplementation cycles.</span>

**한국어 번역:** 이러한 공백을 보완하기 위해 본 연구는 규칙 기반 정적 검사, 검색 증강 생성(RAG) 및 대규모 언어 모델을 결합하여 공식 검토 전에 잠재적인 KCMVP 문제를 식별하는 데 도움을 주는 하이브리드 사전 인증 도구를 제안한다. 이 시스템은 보조적 프로토타입이며 공식 검증을 대체하지 않는다. 또한 본 연구는 실제 보완 주기의 감소를 측정하지 않는다.

**Prototype:** https://github.com/SuBeen-Cho/KCMVP-Compliance-Tool.git

**한국어 번역:** 프로토타입은 위 GitHub 저장소에서 제공한다.

### 1.1 Main Contributions

**Proposal of a hybrid three-stage validation pipeline.**

~~We propose a funnel-shaped three-stage architecture that combines rule-based static detection (L1), guideline evidence retrieval and augmentation (L2), and generative-model-based final decision (L3), thereby improving the balance among detection, explanation, and precision. On 128 Ground Truth cases the pipeline achieved 100% recall, and L3 re-evaluation removed 9 of the 46 FP candidates generated by L1 (19.6%) without inducing any false negatives, yielding a final precision of 77.6% and an F1-score of 87.4%.~~

<span style="color:red">We propose a funnel-shaped three-stage architecture that combines rule-based static detection (L1), evidence retrieval and augmentation (L2), and generative-model-based final decision (L3). In a legacy author-constructed evaluation, 128 labeled cases were reported as detected, and L3 removed 9 of 46 candidates labeled as false positives (19.6%), with no author-labeled TP removed; the reported precision and F1-score were 77.6% and 87.4%. That run lacks an immutable manifest tying it to the current repository snapshot, so these figures are retained as provisional feasibility evidence rather than a general performance estimate.</span>

**한국어 번역:** 본 연구는 규칙 기반 정적 탐지(L1), 증거 검색 및 증강(L2), 생성 모델 기반 최종 판단(L3)을 결합한 퍼널형 3단계 아키텍처를 제안한다. 저자가 구축한 과거 평가에서는 라벨링 사례 128개가 탐지된 것으로 보고되었으며, L3는 오탐으로 라벨링된 후보 46개 중 9개(19.6%)를 제거하되 저자가 라벨링한 참양성은 제거하지 않았다. 보고된 정밀도와 F1 점수는 각각 77.6%와 87.4%이다. 해당 실행을 현재 저장소 스냅샷과 연결하는 불변 매니페스트가 존재하지 않으므로, 이 수치는 일반적인 성능 추정치가 아니라 잠정적인 실행 가능성 근거로 유지한다.

**Systematized KCMVP inspection rule set and domain-specific false-positive mitigation.**

~~We subdivide inspection rules derived from actual KCMVP documents into more than 170 rules across five categories (common security, algorithms, modes of operation, documentation, and traceability) and encode them with four pattern types (missing, regex, semantic, ast) in YAML, enabling systematic management and expansion of a large-scale rule set. A blind verification on a certified commercial module (14.5 KLOC) recorded a low FP rate of 0.58 cases/KLOC, confirming practical applicability.~~

<span style="color:red">We encode 161 YAML rule assets across five categories (common security, algorithms, modes of operation, documentation, and traceability), comprising 92 code-oriented rules, 65 document rules, and four traceability rules. The present implementation and quantitative evaluation are LEA-centered; support for other KCMVP algorithms is treated as future work. A commercial-module case study is retained as a qualitative stress test rather than as an independently labeled FP benchmark.</span>

**한국어 번역:** 본 연구는 공통 보안, 알고리즘, 운용 모드, 문서 및 추적성의 다섯 범주에 걸쳐 총 161개의 YAML 규칙 자산을 인코딩한다. 이는 코드 지향 규칙 92개, 문서 규칙 65개 및 추적성 규칙 4개로 구성된다. 현재 구현과 정량 평가는 LEA를 중심으로 하며, 다른 KCMVP 알고리즘에 대한 지원은 향후 연구로 다룬다. 상용 모듈 사례 연구는 독립적으로 라벨링된 오탐 벤치마크가 아니라 정성적 스트레스 시험으로 제시한다.

**Simultaneous validation of source code and submitted documents.**

By taking as input and preprocessing not only the source code but also the submitted documents (design, configuration management, testing, etc.) that are mandatorily required during the cryptographic module validation process, this tool enables code rules and document rules to be inspected in parallel within the same pipeline. Through this, the system goes beyond static analysis of code alone and also encompasses rule-based inspection of the document deliverables required by the validation authority.

**한국어 번역:** 본 도구는 소스 코드뿐만 아니라 암호모듈 검증 과정에서 의무적으로 요구되는 제출 문서(설계, 형상관리, 시험 등)를 입력받아 전처리함으로써 동일한 파이프라인 내에서 코드 규칙과 문서 규칙을 병렬로 검사한다. 이를 통해 코드 정적 분석을 넘어 검증기관이 요구하는 문서 산출물에 대한 규칙 기반 검사까지 포괄한다.

## 2. Background

### 2.1 Overview of the KCMVP System

The Korean Cryptographic Module Validation Program (KCMVP) is a national certification system operated under Article 9, Paragraphs 2 and 3 of the Cyber Security Work Regulations [cybersec2024] and Article 69 of the Enforcement Decree of the Electronic Government Act [egov2025]. It is the domestic counterpart to the United States' CMVP (FIPS 140-2/3) [fips1402, fips1403], with a similar validation framework and security-requirements structure but differing in the list of approved algorithms and the testing procedures. The purpose of this program is to objectively verify whether the cryptographic modules used in the information systems of government and public institutions satisfy national security requirements. The targets of KCMVP validation are cryptographic modules intended to protect non-classified business data, and they may be implemented as software, hardware, firmware, or a combination thereof.

**한국어 번역:** 한국 암호모듈 검증제도(KCMVP)는 사이버안보 업무규정 제9조 제2항 및 제3항 [cybersec2024]과 전자정부법 시행령 제69조 [egov2025]에 근거하여 운영되는 국가 인증제도이다. 이는 미국 CMVP(FIPS 140-2/3) [fips1402, fips1403]에 대응하는 국내 제도로서 유사한 검증 체계와 보안 요구사항 구조를 가지지만, 승인 알고리즘 목록과 시험 절차에서는 차이가 있다. 이 제도의 목적은 정부 및 공공기관의 정보시스템에서 사용되는 암호모듈이 국가 보안 요구사항을 충족하는지를 객관적으로 검증하는 데 있다. KCMVP 검증 대상은 비밀로 분류되지 않은 업무 데이터를 보호하기 위한 암호모듈이며, 소프트웨어, 하드웨어, 펌웨어 또는 이들의 조합으로 구현될 수 있다.

KCMVP is based on KS X ISO/IEC 19790 (Security Requirements for Cryptographic Modules) [ks19790] and KS X ISO/IEC 24759 (Test Requirements for Cryptographic Modules) [ks24759], and classifies security levels into four grades, from Level 1 to Level 4. This study targets Level 1 software modules, which are the most common subjects of domestic cryptographic module certification.

**한국어 번역:** KCMVP는 KS X ISO/IEC 19790(암호모듈 보안 요구사항) [ks19790]과 KS X ISO/IEC 24759(암호모듈 시험 요구사항) [ks24759]에 기반하며, 보안 수준을 1등급부터 4등급까지 네 단계로 분류한다. 본 연구는 국내 암호모듈 인증에서 가장 일반적인 대상인 1등급 소프트웨어 모듈을 대상으로 한다.

~~The core functions that a cryptographic module must provide are the four security services of confidentiality, integrity, authentication, and non-repudiation, and the KCMVP-approved algorithms include LEA [lea2014], the Korean national standard, as well as international standard algorithms such as AES [aes2023] and SEED [seed2005]. Among these, LEA is the only lightweight block cipher developed domestically, and it is the most frequently used algorithm in KCMVP software implementations. Therefore, this study selects LEA as the main analysis target.~~

<span style="color:red">The core functions that a cryptographic module must provide are the four security services of confidentiality, integrity, authentication, and non-repudiation, and the KCMVP-approved algorithms include LEA [lea2014], the Korean national standard, as well as algorithms such as AES [aes2023] and SEED [seed2005]. This study selects LEA as a bounded initial analysis target; it does not infer prevalence or claim cross-algorithm generalization from the present evaluation.</span>

**한국어 번역:** 암호모듈이 제공해야 하는 핵심 기능은 기밀성, 무결성, 인증 및 부인방지의 네 가지 보안 서비스이며, KCMVP 승인 알고리즘에는 국내 표준인 LEA [lea2014]와 AES [aes2023], SEED [seed2005] 등의 알고리즘이 포함된다. 본 연구는 제한된 초기 분석 대상으로 LEA를 선정하며, 현재 평가로부터 사용 빈도를 추론하거나 알고리즘 간 일반화를 주장하지 않는다.

### 2.2 KCMVP Adoption Criteria and Validation Procedure

Products for which KCMVP certification is mandatorily required fall broadly into three types: (i) information protection systems (firewalls, VPNs, intrusion detection systems, etc.), (ii) quantum cryptographic communication equipment, and (iii) products in which cryptography is the main function. In this respect, unlike hardware and firmware, software modules undergo frequent code modifications, and depending on the scope of change when applying functional improvements or security patches, either full re-validation or partial re-examination is required. This produces recurring temporal and financial burdens even after certification has been obtained.

**한국어 번역:** KCMVP 인증이 의무적으로 요구되는 제품은 크게 (i) 정보보호시스템(방화벽, VPN, 침입탐지시스템 등), (ii) 양자암호통신 장비 및 (iii) 암호 기능이 주기능인 제품의 세 유형으로 구분된다. 이와 관련하여 소프트웨어 모듈은 하드웨어 및 펌웨어와 달리 코드가 빈번하게 변경되며, 기능 개선이나 보안 패치 적용 시 변경 범위에 따라 전체 재검증 또는 부분 재심사가 요구된다. 이에 따라 인증 획득 이후에도 시간적·재정적 부담이 반복적으로 발생한다.

The KCMVP validation procedure proceeds in the following four stages:

**한국어 번역:** KCMVP 검증 절차는 다음 네 단계로 진행된다.

1. **Validation Application:** The cryptographic module developer organization applies to the testing agency (KISA) for validation, submitting the source code, detailed design specification, test specification, configuration management document, and operator/user manual.
2. **Document Review:** The testing agency verifies the formal completeness of the submitted documents and whether they satisfy basic requirements.
3. **Technical Review (Main Examination):** The testing agency rigorously tests the correctness of the algorithm implementation in the source code, compliance with secure coding practices, and the traceability between code and documents.
4. **Final Deliberation and Certification:** The validation authority (NIS) finally confirms whether the test results meet the standards and then issues the certificate.

**한국어 번역:**

1. **검증 신청:** 암호모듈 개발기관은 소스 코드, 상세설계서, 시험서, 형상관리문서 및 운영자·사용자 설명서를 제출하여 시험기관(KISA)에 검증을 신청한다.
2. **문서 검토:** 시험기관은 제출 문서의 형식적 완전성과 기본 요구사항 충족 여부를 확인한다.
3. **기술 검토(본심사):** 시험기관은 소스 코드의 알고리즘 구현 정확성, 안전한 코딩 관행의 준수 여부 및 코드와 문서 간 추적성을 엄격하게 시험한다.
4. **최종 심의 및 인증:** 검증기관(NIS)은 시험 결과의 표준 충족 여부를 최종 확인한 후 인증서를 발급한다.

~~The entire process typically takes about one and a half years. In particular, supplement requests arising during the technical review process cause additional delays of several weeks to several months at each cycle. Such repeated delays lead to increased validation costs and delayed product release schedules, and they create a practical demand for an automated pre-certification tool. Accordingly, this study proposes an automated pipeline to address this problem.~~

<span style="color:red">The process can be lengthy, and supplement requests during technical review can add repeated correction, retesting, and resubmission work. This creates a practical motivation for an auxiliary pre-certification tool; the present study does not measure certification-time or cost reduction in operational deployments.</span>

**한국어 번역:** 해당 절차는 장기간이 소요될 수 있으며, 기술 검토 중 발생하는 보완 요청은 반복적인 수정, 재시험 및 재제출 작업을 추가할 수 있다. 이는 보조적인 사전 인증 도구에 대한 실무적 필요성을 제기한다. 다만 본 연구는 실제 운영 환경에서 인증 기간이나 비용의 감소를 측정하지 않는다.

### 2.3 LLM- and RAG-based Technologies

A Large Language Model (LLM) is a neural network model pre-trained on massive amounts of code and natural language data, and it is used in a variety of software analysis tasks such as code understanding, pattern recognition, and natural language generation [llmsurvey2023].

**한국어 번역:** 대규모 언어 모델(LLM)은 방대한 코드 및 자연어 데이터로 사전학습된 신경망 모델이며, 코드 이해, 패턴 인식 및 자연어 생성과 같은 다양한 소프트웨어 분석 작업에 활용된다 [llmsurvey2023].

~~Google's Gemini 2.5 Flash-Lite [gemini25], used at the L3 stage of this paper, is a multimodal large language model (LLM) optimized for low cost and high throughput; because it is optimized for low cost and high throughput and supports long context inputs, it is suitable for the L3 decision stage of this study, which jointly handles large code fragments and evidence documents.~~

<span style="color:red">Google's Gemini 2.5 Flash-Lite [gemini25], used at the L3 stage of this paper, supports long context inputs and was selected for prototype L3 decisions over code fragments and supporting evidence.</span>

**한국어 번역:** 본 논문의 L3 단계에서 사용하는 Google Gemini 2.5 Flash-Lite [gemini25]는 긴 컨텍스트 입력을 지원하며, 코드 조각과 보조 증거를 대상으로 하는 프로토타입 L3 판단을 위해 선정하였다.

Retrieval-Augmented Generation (RAG) is a methodology that combines external knowledge-based evidence with the responses of LLMs [rag2020]. Since LLMs may not have included domain-specific regulations such as KCMVP guidelines in their pre-training data, a RAG architecture that dynamically injects external knowledge is needed. In this system, the Retrieval part of RAG is performed at the L2 stage to search the KCMVP guideline articles, and the retrieved evidence is inserted into the Gemini prompt context at the L3 stage.

**한국어 번역:** 검색 증강 생성(RAG)은 외부 지식 기반 증거를 LLM의 응답과 결합하는 방법론이다 [rag2020]. LLM의 사전학습 데이터에는 KCMVP 지침과 같은 도메인 특화 규정이 포함되지 않았을 수 있으므로, 외부 지식을 동적으로 주입하는 RAG 아키텍처가 필요하다. 본 시스템에서 RAG의 검색 단계는 L2에서 KCMVP 지침 조항을 탐색하며, 검색된 증거는 L3의 Gemini 프롬프트 컨텍스트에 삽입된다.

### 2.4 Related Work

Table 1 compares the proposed system with related prior work along five functional dimensions. The comparison targets are representative prior studies on static-analysis-based detection of cryptographic misuse (CryptoGuard, CogniCrypt) and the algorithm testing automation tool of the U.S. CMVP ecosystem (CAVP).

**한국어 번역:** 표 1은 다섯 가지 기능 차원에서 제안 시스템과 관련 선행연구를 비교한다. 비교 대상은 정적 분석 기반 암호 오용 탐지의 대표적인 선행연구(CryptoGuard, CogniCrypt)와 미국 CMVP 생태계의 알고리즘 시험 자동화 도구(CAVP)이다.

CryptoGuard [cryptoguard2019] leverages an inter-procedural slicing technique to detect 16 categories of cryptographic API misuse in Java. CogniCrypt [cognicrypt2017] provides IDE-integrated inspection for the use of the Java Cryptography Architecture (JCA). Both tools have demonstrated the effectiveness of automated cryptographic-code inspection, but they do not address KCMVP-specific requirements or LEA.

**한국어 번역:** CryptoGuard [cryptoguard2019]는 프로시저 간 슬라이싱 기법을 활용하여 Java에서 16개 범주의 암호 API 오용을 탐지한다. CogniCrypt [cognicrypt2017]는 Java Cryptography Architecture(JCA) 사용에 대한 통합개발환경 연계 검사를 제공한다. 두 도구 모두 암호 코드 자동 검사의 효과를 입증하였으나 KCMVP 고유 요구사항이나 LEA는 다루지 않는다.

The Cryptographic Algorithm Validation Program (CAVP) [cavp], operated by the U.S. NIST, is an algorithm testing automation tool focused on verifying the correctness of test vectors. It verifies the mathematical correctness of algorithm implementations based on publicly available test vectors, but does not provide functionality for analyzing implementation context in the source code or for verifying document traceability. Korea's existing KCMVP pre-certification system is likewise limited to test-vector accuracy testing [nsrguide2023]. Thus, while existing studies have demonstrated the feasibility of automating cryptographic-code inspection, no tool exists that simultaneously supports the incorporation of KCMVP-specific requirements, LLM-based semantic decision-making, and automated traceability between source code and documents. This study proposes a three-stage hybrid pipeline that integrates these three functions.

**한국어 번역:** 미국 NIST가 운영하는 Cryptographic Algorithm Validation Program(CAVP) [cavp]은 시험 벡터의 정확성 검증에 초점을 둔 알고리즘 시험 자동화 도구이다. 이 도구는 공개 시험 벡터에 근거하여 알고리즘 구현의 수학적 정확성을 검증하지만, 소스 코드의 구현 컨텍스트를 분석하거나 문서 추적성을 검증하는 기능은 제공하지 않는다. 국내의 기존 KCMVP 사전검증 체계 역시 시험 벡터 정확성 시험에 한정된다 [nsrguide2023]. 따라서 기존 연구는 암호 코드 검사의 자동화 가능성을 제시하였으나, KCMVP 고유 요구사항의 반영, LLM 기반 의미론적 판단 및 소스 코드와 문서 간 자동 추적성을 동시에 지원하는 도구는 존재하지 않는다. 본 연구는 이 세 기능을 통합하는 3단계 하이브리드 파이프라인을 제안한다.

**Table 1. Comparative analysis with related prior work. ✓ = supported, × = not supported.**

| System | Target | Crypto. Insp. | LLM decision | Doc. Insp. | Traceability | Evidence matching |
|---|---|:---:|:---:|:---:|:---:|:---:|
| CryptoGuard [cryptoguard2019] | Java API | ✓ | × | × | × | × |
| CogniCrypt [cognicrypt2017] | Java JCA | ✓ | × | × | × | × |
| CAVP [cavp] | Test vectors | ✓ | × | × | × | × |
| Proposed system | KCMVP | ✓ | ✓ | ✓ | ✓ | ✓ |

**한국어 번역 — 표 1. 관련 선행연구와의 비교 분석. ✓는 지원함을, ×는 지원하지 않음을 의미한다.**

| 시스템 | 대상 | 암호 검사 | LLM 판단 | 문서 검사 | 추적성 | 증거 매칭 |
|---|---|:---:|:---:|:---:|:---:|:---:|
| CryptoGuard [cryptoguard2019] | Java API | ✓ | × | × | × | × |
| CogniCrypt [cognicrypt2017] | Java JCA | ✓ | × | × | × | × |
| CAVP [cavp] | 시험 벡터 | ✓ | × | × | × | × |
| 제안 시스템 | KCMVP | ✓ | ✓ | ✓ | ✓ | ✓ |

## 검토 메모

- 이 범위에는 독립된 표시 수식이 없다. 본문의 `19.6%`, `77.6%`, `87.4%`, `~14.5 KLOC` 등의 수치는 해당 변경 문단 안에 모두 보존하였다.
- 변경되지 않은 문단도 모두 수록하고 각 문단 아래에 학술체 한국어 번역을 제공하였다.
- LaTeX의 구조 명령, 레이아웃 명령 및 줄바꿈 명령은 Markdown 표현으로 변환하였으며, 의미를 갖는 제목·문단·열거·표·인용 키는 보존하였다.

---

# 3. System Design — 완전성 보존 검토본

> 기준 원문: `03system_design.tex` (2026-08-11)
> 원문 완전성을 우선하여 아래 제1부에 LaTeX 원문 395행을 그대로 보존한다. 그림은 이미지 대신 캡션 명령만 남긴다.

## 제1부. 최신 영문 원문(완전 보존)

```latex
%====================================================================
\section{System Design}
\label{sec:design}

\subsection{Design Goals}

To maximize detection accuracy while minimizing False Positives, this pre-certification system subdivides the overall validation process into three mutually complementary stages: rule-based deterministic detection (L1), RAG-based guideline evidence retrieval (L2), and LLM-based final decision (L3).

\textbf{Goal~1. Ensuring High Recall.}
This study aimed to achieve high recall through pattern-based deterministic detection. In particular, by applying the \texttt{missing} (absence of required patterns) and \texttt{regex} (string pattern match) types as explicitly defined rules, we pursue a broad-coverage search aimed at reducing omissions for violations that can be expressed as rules.

\textbf{Goal~2. Minimizing False Positives (FP).}
Because simple rule-based detection may structurally include false positives (similar patterns, constants, and test code), this study aims to minimize false positives by examining both code and document context together with evidence through domain-specific filters and the LLM's final decision.

\textbf{Goal~3. Evidence-based Simultaneous Validation of Code and Documents.}
This framework processes the source code (ZIP) and submitted documents (PDF) in an integrated manner within a single pipeline, and through the three-tier RAG retrieval at the L2 stage, it automatically attaches actual KCMVP guideline articles to each detected violation item, thereby securing the interpretability of validation results.

\subsection{Overall System Architecture}

The overall pipeline is designed as a funnel structure as shown in Fig.~\ref{fig:pipeline}. First, the source code (ZIP) and the submitted documents are received together and preprocessed. On the code side, the system builds a structural summary containing function and call information along with a symbol graph that links calls across files; on the document side, body text and tables are extracted from the PDF and then structured into a section list using the table of contents and the like. This broadly secures the coordinates (file, line, section) at which rules can be applied.

\begin{figure}[!t]
\centering
\caption{Overall pipeline configuration diagram.}
\label{fig:pipeline}
\end{figure}

At the subsequent L1 stage, inspection rules defined in YAML are applied across four pattern types. \texttt{missing} handles the absence of required elements, \texttt{regex} handles string-pattern matching, \texttt{semantic} handles keyword and contextual cues, and \texttt{ast} handles syntactic/structural cues. When this stage passes through heuristic filters, the broadly captured error-suspect list is consolidated into a candidate set.

At the next stage, KCMVP guideline evidence is retrieved and matched, centered on the rule identifier and the suspected code/paragraph (the suspect part). Evidence documents loaded into ChromaDB or similar stores can be utilized. The evidence documents are stored in markdown by dividing the KCMVP specification documents into topic and article units.

Next, the generative model receives the suspect part, decision instructions, and evidence together, and ultimately distinguishes false positives from actual violations. The flow of refining the broadly captured candidates from the previous stage through evidence- and context-based decisions corresponds to the narrowing section of the funnel. Eventually, the outcomes are consolidated into deliverables such as patch notes and reports, and rejected items are also kept as candidate history if needed so that they can be tracked.

In addition, although omitted from the figure for clarity, in the implementation the evidence retrieval is invoked twice: once when constructing the prompt for LLM decision-making, and again, by the same module, when attaching evidence fields to the final violation list. The former is to inject specification evidence into the decision context, and the latter is to enable per-violation evidence to be verified in the report and UI.

Table~\ref{tab:stages} summarizes the main functions and roles at each stage.

\begin{table}[!t]
\centering
\caption{Per-stage summary of the proposed KCMVP pre-certification pipeline.}
\label{tab:stages}
\footnotesize
\setlength{\tabcolsep}{3.5pt}
\renewcommand{\arraystretch}{1.13}

\begin{tabular}{
@{}
>{\centering\arraybackslash}m{1.7cm}
>{\raggedright\arraybackslash}m{4.25cm}
>{\raggedright\arraybackslash}m{6.6cm}
@{}}
\toprule
\textbf{Stage} & \textbf{Analysis method} & \textbf{Main objective} \\
\midrule

\shortstack{Pre-\\processing}
  & Source normalization; four-stage AST fallback; symbol graph construction; document OCR sectioning
  & Generating file, line, section, and call-relationship coordinates for rule application \\
\midrule

L1
  & Per-pattern-type rule application; domain-anchor-based candidate refinement
  & Deterministic primary candidate detection and reduction of obvious false positives \\
\midrule

L2
  & Three-tier RAG retrieval
  & Attaching KCMVP evidence and decision context for each candidate \\
\midrule

L3
  & Semantic re-evaluation
  & Distinguishing actual violations from false positives and conservatively removing candidates \\
\midrule

TRC
  & Cross-comparison of header APIs, source definitions, and documents
  & Traceability inspection across specifications, code, and test specifications \\
\bottomrule
\end{tabular}
\end{table}

\subsection{Per-stage Design of the Validation Pipeline}

\subsubsection{Preprocessing Stage.}

The rule engine and the LLM need location information that can be referenced repeatedly---such as file paths, source line numbers, document sections, and tables---so that they can write violation descriptions consistently for the same input and so that the surrounding code and paragraphs around the problematic location can be sliced and passed as context. Furthermore, security and implementation inspections are difficult to grasp with simple string searches alone, and the judgment becomes more accurate only when structural and call information---such as where a function is called from and what it calls---is available. Accordingly, a preprocessing step was introduced that converts source code into line-by-line text together with function-and-call summaries, and converts documents into separated body/table representations with a section-level structure, in order to improve accuracy. Specifically, structural information is extracted from the uploaded ZIP archive and PDF documents to generate analysis artifacts in JSON form.

\paragraph{AST and Symbol Graph.}
The Abstract Syntax Tree (AST) is an intermediate representation that expresses the syntactic structure of source code in tree form, and it is the standard output of the parsing stage in compiler design~\cite{aho2006}. The symbol graph is a structured representation that connects symbolic information---such as function definitions, function calls, and global constant arrays extracted from multiple source files---through nodes and edges.

Because the AST focuses on how operations and statements are arranged and in what structure within a single file or function, it is suitable for inspecting implementation invariants inside a function; the symbol graph, by contrast, shows where each function is defined and which functions in other files it calls, and is therefore used to judge cross-file relationships such as cross-file zeroization and wrapper calls.

The C preprocessing stage directly affects the analysis results. In C/C++, the standard preprocessor (\texttt{\#define}, \texttt{\#include}, \texttt{\#ifdef}) can directly modify the source structure at the token level prior to parsing, and this may cause the original-source location information and the actual syntactic structure after preprocessing to diverge. Because the C parser and rule engine rely not on a mere sequence of tokens but on types, constant values, macro expansion results, identifier interpretation becomes difficult and a malformed node structure may be generated if scattered headers are not appropriately restored.

Accordingly, this system combines \texttt{gcc~-E} preprocessing, internal header tracking, and libclang-based AST and symbol graph construction, and adopts the following multi-stage fallback structure to improve the parsing success rate.

\begin{enumerate}
\item \textbf{Stage~1. libclang-First Parsing:} Full parsing of the source file is attempted using LLVM libclang. Since macro expansion and header inclusion are handled internally, the syntax tree can be constructed accurately even given the complex header dependencies often found in cryptographic module code. If parsing succeeds, the function definitions and call relationships are constructed to generate an AST summary together with the symbol graph.

In the libclang parsing path, the system collects not only simple call information but also type information and cross-file linkage information. In the symbol graph generated through libclang, the key is the linkage based on Unified Symbol Resolution (USR). When functions with the same name exist across multiple files, or when the header declaration is separated from the implementation definition, simple name matching alone can leave the call target ambiguous. Because libclang allows the USR to be obtained from the referenced cursor of a function definition and a call expression, this system first links calls to definition locations via the USR, and falls back to name-based matching only when the USR is empty. For this reason, the call relationships in the symbol graph include not only the calling file, calling line, and called function name, but, when possible, also the definition file and definition line of the called function.

In addition, the libclang path stores typedef aliases and static constant-array initialization values as separate evidence. typedefs are used to interpret \texttt{uint32\_t}, function pointer types, and public API signatures, while static constant arrays are used to distinguish public constants---such as LEA delta, S-box, lookup table, and KAT/vector---from candidate secret keys. For arrays, the system locates \texttt{CONSTANTARRAY}-typed entries among \texttt{VAR\_DECL}s, extracts tokens from the initialization list, and stores the variable name, element type, size, and initial-value samples in \texttt{array\_inits}. This value later serves as the key evidence for determining whether a hard-coded key candidate is an actual secret key or a public algorithmic constant.

\item \textbf{Stage~2. gcc~-E + pycparser Preprocessing:} When libclang is unavailable or when a pycparser-based fallback is required, the system first uses the compiler's \texttt{gcc~-E} preprocessing to produce C text with macros expanded, and then parses it with pycparser.

In this case, parsing along the pycparser path is focused not on reproducing the entire compilation environment but on recovering, as stably as possible, the function definitions and call locations required for KCMVP pre-certification. To prevent errors in LLM judgment, block comments and line comments are removed while the number of newlines is preserved, so that the original line numbers are not skewed. As a result, the violation locations output by L1 and the code slices received by L3 can directly point to the original file locations submitted by the user.

Next, types and standard function declarations that frequently appear in cryptographic implementations---such as \texttt{uint32\_t}, \texttt{size\_t}, \texttt{memset}, and \texttt{memcpy}---are inserted as a minimal preamble. For local headers, \texttt{\#include} is followed recursively, numeric macros are converted into \texttt{enum(NAME = VALUE);}, simple alias macros into \texttt{typedef}, and function-like macros into fake declarations of the form \texttt{int NAME(int arg, ...);}. This processing removes most preprocessor directives while preserving the name information required for AST extraction---such as array sizes, type names, and macro function calls.

\item \textbf{Stage~3. Full Preprocessing:} This is the fallback stage when the compiler preprocessor cannot be used, and its purpose is to reflect, as much as possible, the type and name information contained in project-local headers even without a system preprocessor. After following only the quoted \texttt{\#include} directives within the project to read headers, comments are removed, and only function-like macros whose name is immediately followed by a parenthesis---such as \texttt{\#define} entries---are picked out and converted into fake function declarations of the form \texttt{int name}. These fixed declarations and macro declarations are placed at the front, and the body with directive lines removed is appended for parsing.

\item \textbf{Stage~4. Simple Preprocessing:} If the working root or file paths are missing, or if parsing with header inclusion fails, the system retries using only the fixed preamble and the in-source macro declarations. Only the preamble and the in-source \texttt{\#define} macros are processed. If the procedure fails even at Stage~3, parsing is performed on the body alone after removing comments and replacing only preprocessor directive lines with blank lines.
\end{enumerate}

If parsing fails at any stage, the system automatically switches to the next stage, and line-number differences caused by preamble insertion are converted back to the actual line numbers of the original source code via offset correction. Listing~\ref{lst:ast} shows an example of the JSON structure of the AST preprocessing result.

\Needspace{18\baselineskip}
\begin{lstlisting}[language=json,caption={JSON schema of the AST preprocessing result.},label={lst:ast}]
{
  "path": "src/lea_key.c",
  "ast": {
    "functions": [
      {
        "name": "lea_encrypt",
        "line": 8, "end_line": 20,
        "calls": [
          {"name":"lea_set_key","line":10},
          {"name":"memset_s","line":19}
        ]
      }
    ],
    "file_calls": [
      {"name":"lea_set_key","line":10},
      {"name":"memset_s","line":19}
    ]
  }
}
\end{lstlisting}

\paragraph{Document Section Extraction.}
For documents, two libraries were utilized in order to correctly extract the text of both running prose and tables. Because tables require restoration of their grid structure, pdfplumber~\cite{pdfplumber} is used to detect table candidates within each page, and table data is built as a two-dimensional array based on cell boundaries. At the same time, the bounding box of each table is recorded, and when PyMuPDF~\cite{pymupdf} is used to extract body text, text blocks that substantially overlap with such a box---measured by area---are excluded from the body candidates. The purpose of this design is to prevent the same content from being duplicated across running text and the table structure, and to separate the roles of each so that tables are kept as structured representations while other descriptions are kept as running body text.

After extracting both text and tables, section separation is performed so that violation regions can be expressed at the paragraph level. Section separation proceeds along two paths---table-of-contents-based and body-header-pattern-based---with the table-of-contents-based path taken first.

\begin{enumerate}
\item \textbf{Stage~1. Table-of-Contents-First Path:} After searching for the table of contents or ``Contents'' in the full text concatenated across pages, regular expressions corresponding to entries like ``1. Title\ldots\ 4'', ``Chapter N'', ``Section'', or ``Article page'' are used to extract, for each entry, the identifier, title, and in-document page number. Then, by finding the physical page on which a word from the title of the first entry reappears in the body, the offset between the printed page numbers in the table of contents and the physical PDF pages is computed. For each table-of-contents segment, the body of the offset-corrected physical-page range is concatenated, and only tables falling within the same page range are attributed to that section. From the body text, page headers and footers and page markers consisting entirely of Arabic numerals on a single line are removed so that unnecessary text is not included.

\item \textbf{Stage~2. Header-Pattern Path:} When no table of contents exists or when the procedure above fails to produce valid sections, the integrated body string is scanned line by line, and hierarchical-heading candidates are identified by regular expressions. After identification, the beginning of each section's body is located within the entire string to approximate the starting and ending physical pages.
\end{enumerate}

Each per-section object holds the document type determined by the uploaded document's path, a logical file key obtained by appending the section identifier after the relative path with respect to the working root, the section title, the hierarchical depth inferred from the table of contents or header pattern, the start page and end page that the body occupies, the body text of that section, and the list of tables falling within that page range.

If neither header nor table of contents can be obtained from the two stages above, the entire file is grouped and marked as a single section. Ultimately, the unit of document preprocessing is divided into sections so that L3 can receive only the necessary sections together with adjacent sections to re-evaluate the document context.

Scanned PDFs without a text layer are automatically detected, and the Gemini 2.0 Flash Vision OCR model~\cite{gemini20flash} is used to recognize each page image and extract text. This also enables automated rule validation on scanned documents.

\subsubsection{L1: Rule-based Static Analysis.}

L1 is the layer that receives the outputs handed over by preprocessing and mechanically applies the inspection rules defined in the repository to produce a set of violation candidates. Fig.~\ref{fig:l1} illustrates the overall flow of L1.

\begin{figure}[H]
\centering
\caption{L1 pipeline flow.}
\label{fig:l1}
\end{figure}

The inputs supplied through preprocessing include, for each source file collected relative to the working root, the original text, the body with comments removed, the per-file AST summary (function definitions, function call lists, etc.), and the project-wide symbol graph (call relationships across files, the set of files defining zeroization-related calls, etc.). Based on this information, the rule engine evaluates the conditions declared in YAML.

\begin{table}[!htbp]
\centering
\caption{System rule-asset domains and execution paths.}
\label{tab:rulecats}
\small
\begin{tabular}{@{}llp{6cm}@{}}
\toprule
Category & ID & Main inspection items \\
\midrule
Common security & COM-xxx & Module-wide common security \\
LEA & LEA-xxx & LEA-specific constraints \\
Modes of operation & CBC/CTR/GCM/\ldots & Per-mode-specific constraints \\
Documents & DOC-xxx & Separate document-validation service \\
Traceability & TRC-xxx & Separate design--code--test traceability service \\
\bottomrule
\end{tabular}
\end{table}

Table~\ref{tab:rulecats} shows the system asset domains. The 92 code-oriented assets execute in L1, 65 document assets execute in the document-validation service, and four traceability assets use a separate custom schema and service. The four pattern types below apply to the 157 code and document assets, not to the four traceability assets.

\paragraph{Detection Pattern Types.}
Table~\ref{tab:patterns} outlines the detection principle of L1 rules by pattern type and how the resulting violations are linked to the LLM-based re-evaluation stage (L3). Because the four types differ in the nature of the evidence each rule requires---absence, string, or syntactic structure---the same pipeline assigns different levels of reliability and downstream weight to each.

\begin{table}[t]
\centering
\caption{Detection pattern types and their linkage to the L3 stage.}
\label{tab:patterns}
\small
\begin{tabular}{@{}llll@{}}
\toprule
Type & Detection principle & Details & L3 \\
\midrule
\texttt{missing} & Absence check & Required pattern omitted & Optional \\
\texttt{regex} & Regular expression & Pattern matching & Optional \\
\texttt{semantic} & keyword + AI & Context-required pattern & Priority \\
\texttt{ast} & AST analysis & Structural inspection & Priority \\
\bottomrule
\end{tabular}
\end{table}

\begin{enumerate}
\item \textbf{\texttt{missing}} -- An absence-type rule yields a violation when the regular expression described in \texttt{pattern} is not observed at all in the body after comment removal. The unit of application varies between \texttt{file} and \texttt{project} depending on \texttt{scope}, with the latter compressing the fact that the same signal never appeared anywhere in the repository into a single violation.

\item \textbf{\texttt{regex}} -- The compiled pattern is applied across the entire original text; the line range is computed from the start and end offsets of the matched section, and each match is recorded as an independent violation. For specific identifiers, heuristic filtering is applied by means such as excluding surrounding context, variable names, and comment lines. Because objective string-level matching is the core principle, reliability is kept relatively high, but, depending on severity, items are classified for L3 re-evaluation.

\item \textbf{\texttt{semantic}} -- A semantic-type rule treats a pattern as a keyword/trigger condition, but also includes cases that append additional procedures per identifier. If the keyword is not observed, a file- or project-level candidate violation reflecting the possibility of a missing topic is generated, and metadata is recorded indicating that the item should later be reviewed at the LLM-based semantic re-evaluation stage. If scope is not explicitly restricted to \texttt{file}, aggregation switches to the project level to suppress repeated occurrences of the same signal. Because this type requires contextual re-interpretation, it is re-evaluated at L3.

\item \textbf{\texttt{ast}} -- A syntactic-type rule is for cases where the full context is needed, and a dedicated checker that directly judges the structural properties of the Abstract Syntax Tree (AST) produced through preprocessing is run preferentially. Dedicated checker mappings currently cover 25 LEA rule identifiers through 24 distinct checker implementations, because one rule identifier shares an implementation. If the checker detects a rule violation, it is flagged; if no violation is found, the rule is considered satisfied and the inspection terminates. Through this, the code lines suspected of violation are extracted as a candidate group and re-evaluated at the L3 stage.
\end{enumerate}

\paragraph{Domain-Anchor-based Candidate Refinement.}
In this study, a domain anchor is a structural and contextual cue used---before applying a given rule---to judge whether the analyzed file or code fragment falls within the semantic scope of that rule. The L1 rule engine generates candidates broadly to achieve high recall, but because cryptographic module submissions contain public constants, test vectors, wrappers, benchmarks, and mode-of-operation-specific files, together, simple rule application alone increases false positives. Accordingly, this system uses anchors before and after rule application to refine the candidates.

Domain anchors are broadly divided into identification anchors and exclusion anchors. An identification anchor is evidence that strengthens the case that a particular piece of code is an actual rule-application target. For example, when LEA round loops, accesses to round-key arrays, ROL/ROR-based ARX operations, and references to the delta constant appear together, the file is likely to be a LEA implementation file. Conversely, an exclusion anchor is evidence that excludes targets which superficially look like violations but are not violations in the actual validation context. The LEA delta constant, KAT input values, S-boxes, wrappers' simple delegation functions, and benchmark-only fixed plaintexts fall into this category.

Candidate refinement in this system uses both kinds of anchors together to retain structural violations that should be detected while reducing low-value false-positive evidence. Through this, the candidate quality of L1 is improved, and only candidates that genuinely require contextual judgment are forwarded to L3.

\Needspace{18\baselineskip}
\begin{lstlisting}[language=yaml,caption={YAML-structure summary of the COM-001 rule.},label={lst:yaml}]
- id: COM-001
  name: "Residual data clearing (zeroization)"
  category: common
  scope: project
  pattern_type: "missing"
  pattern: "<safe zeroization API names>"
  severity: high
  kcmvp_ref: "KS X ISO/IEC 19790:2015 ..."
\end{lstlisting}

\paragraph{YAML Rule-Set Structure.}
Listing~\ref{lst:yaml} shows an example of a YAML-based rule set generated based on the Table~\ref{tab:patterns} patterns. Rules are identified and classified by \texttt{id}, \texttt{name}, \texttt{category}, and \texttt{scope}; the pattern is set in \texttt{pattern\_type}, and the regular expression is entered in \texttt{pattern}. \texttt{severity} and \texttt{kcmvp\_ref} are auxiliary information for severity grading and evidence citation.

\subsubsection{L2: RAG-based Evidence Matching.}

L2 is the stage that supplies context through evidence retrieval and input construction. Fig.~\ref{fig:l2} illustrates the overall flow of the L2 stage. The violation candidates identified at L1 are passed in as individual instances, and for each item, the minimal metadata required for decision-making---rule identifier, pattern type, file and line location, violation description, and so on---is organized. At the same time, the surrounding source (or document) segment around that location is extracted as a code/document slice in order to reduce the input tokens to the model while still preserving context.

\begin{figure}[H]
\centering
\caption{L2 pipeline flow.}
\label{fig:l2}
\end{figure}

Next, by matching with rule \texttt{id} as the key, evidence documents are attached from KCMVP-related guidelines and technical materials stored in the DB. Finally, the collected slices, violation descriptions, and retrieved evidence are bundled into a single prompt together with the header, system role, and output-format instructions, and submitted to the language model; the response is then forwarded to L3.

\paragraph{Decision-Use Context Excerption.}
If the entire original text is fed verbatim to the language model, cost and latency grow with the input length, and as more unrelated sentences appear, attention is diluted and decision quality may degrade. Accordingly, only the minimal contiguous segment necessary for judgment is excerpted. The excerpt width is varied to match the pattern type and the document structure, preserving local context---such as call relationships, surrounding conditions, and the flow across adjacent clauses---without breaking continuity, while staying within the token budget.

\begin{enumerate}
\item \textbf{Code Slicing.} Based on the file path and line position, a contiguous block of source lines centered on that point is sliced to compose a snippet for decision-making. The window size before and after is varied by pattern type: \texttt{regex} violations use narrow context, while \texttt{semantic}/syntactic candidates use relatively wider context so that surrounding declarations and call relationships can also be examined.

\item \textbf{Document Excerption.} For document re-evaluation, the system relies on the clause-level structure obtained from preprocessing, but instead of showing only a specific clause, it bundles several clauses belonging to the same document type in order to create a single block of context. The intent is to also examine whether equivalent content is described in other clauses even if the clause flagged by the violation contains no keywords. However, because the body of each clause can be very long, only the front portion of each clause is sliced so that a single clause does not occupy the entire input, and an overall upper bound is also placed on the concatenated string when multiple clauses are joined, thereby controlling the amount and cost the model processes at once.
\end{enumerate}

\paragraph{Three-Tier Retrieval Structure.}
Evidence retrieval is divided into three stages, with a direct mapping attempted first. The current corpus contains author-prepared guidance and mappings derived from the cited requirements; it must not be interpreted as a verbatim or authoritative reproduction of an official guideline. When a direct mapping is absent or insufficient, semantic search retrieves related passages, followed by a broader keyword and similarity search. Retrieved passages are supporting context rather than independent validation.

\begin{enumerate}
\item \textbf{Direct Mapping (Tier~1):} Corresponding to the rule-set identifier (\texttt{id}), designated author-prepared guidance is loaded. It was constructed as candidate evidence chunks derived from cited cryptographic-module documents~\cite{kisaguide2025,leaspec,nisimpl2024}. An explicit author-maintained rule--guidance link makes the mapping inspectable, but it is neither an independent validation nor an authoritative reproduction of the source.

\item \textbf{ChromaDB Vector Search (Tier~2):} This is a path that splits the guideline markdown into clause/paragraph units in the vector store (ChromaDB), encodes each fragment as a real-valued vector using an embedding model, projects the query sentence into the same space, and selects semantically similar fragments. When a specific guideline clause has already been secured by Direct Mapping, the existing list is not replaced; instead, a vector search is performed with the same query, and a small number of fragments from different sources are appended to broaden the evidence. When Direct Mapping is empty, metadata such as article identifiers is used as a filter to find chunks semantically close to the query, which serve as the primary returned results. Through this, meaningful evidence is reinforced or substituted without breaking the explicit rule--document linkage.

\item \textbf{TF-IDF Keyword Fallback (Tier~3):} The TF-IDF path ranks each chunk by a similarity score that reflects the term frequency and the rarity across the document set as a whole, and returns only a small top-$k$. The query is either provided at call time or uses the search phrase stored in the rule mapping. It is invoked as a last resort when vector search is disabled or fails to produce valid results; while it does not guarantee semantic agreement, it serves as a conservative safety net that quickly retrieves lexically close clauses from a broad document set to mitigate evidence gaps.
\end{enumerate}

The evidence chunks selected and ordered as above are injected into the prompt as a reference-guideline block, and they are also added to the evidence field of the final report JSON in summary form to provide evidence.

\paragraph{Prompt Construction.}
After the above excerption and evidence retrieval, the prompt is constructed. Going beyond simple role instructions and code-insertion structures, the prompt design of this system adopts a Hierarchical Hybrid Prompting architecture that combines eight techniques across three tiers in order to simultaneously achieve decision accuracy and false-positive suppression.

\begin{table}[!t]
\centering
\caption{Configuration of the Hierarchical Hybrid Prompting architecture.}
\label{tab:prompting}
\footnotesize
\setlength{\tabcolsep}{5pt}
\renewcommand{\arraystretch}{1.08}

\begin{tabular}{
@{}
>{\raggedright\arraybackslash}m{4.6cm}
>{\raggedright\arraybackslash}m{8.4cm}
@{}}
\toprule
\textbf{Technique} & \textbf{Role} \\
\midrule

\multicolumn{2}{@{}l}{\textbf{Judgment-frame setting}} \\
Persona Prompting
  & Assigns the role of a KCMVP reviewer \\
RAG Guideline
  & Injects specification evidence into the prompt \\
GCFS
  & Summarizes the project-wide key lifecycle \\

\midrule

\multicolumn{2}{@{}l}{\textbf{Per-rule judgment execution}} \\
Few-shot examples
  & Provides violation, normal, and FP decision examples \\
Structured evidence
  & Makes type, array, and call-path evidence explicit \\
Chain-of-Thought (CoT)
  & Guides stepwise reasoning \\
Confidence request
  & Supports post-processing using a 0--100 confidence score \\

\midrule

\multicolumn{2}{@{}l}{\textbf{Result-safety verification}} \\
Asymmetric FP threshold
  & Imposes a higher confirmation cost for false-positive removal \\
Double verification
  & Provides a second-pass review intended to reduce FN risk \\
Rejudge
  & Re-reviews low-confidence violations \\

\bottomrule
\end{tabular}
\end{table}


Tier~1 serves as a judgment frame. Persona Prompting assigns the model the role of a ``KCMVP cryptographic-module security review expert.'' RAG injection places retrieved author-prepared, requirement-derived guidance into the prompt as supporting context. GCFS (Global Code Flow Context Injection) compresses the function definitions and call relationships of the symbol graph into a per-file key-lifecycle flow, conveying to the model the project-wide key creation -- use -- destruction flow that is not visible from a single snippet alone.

Tier~2 is applied selectively according to the characteristics of each rule. Few-shot examples are provided for 18 rules that are difficult to grasp contextually, presenting boundary-case decision criteria as concrete code patterns through violation, normal, and FP code examples. Structured evidence explicitly inserts type aliases, array initialization values, function parameters, and call paths for rules that depend on the AST checker and the symbol graph. CoT is applied to 23 rules in which multi-step contextual understanding is critical---such as LEA round-key index boundaries and the CBC/CTR/GCM initialization order---and makes the stepwise reasoning order explicit to guide the model's chain of reasoning. The confidence request requires, for every candidate, a $0$--$100$ integer in the \texttt{confidence} field, and this value is utilized in the Tier-3 post-processing.

Tier~3 is a conservative post-processing layer. The asymmetric FP threshold sets confidence $< 25$ for \texttt{ast}/\texttt{semantic} candidates and confidence $< 40$ for \texttt{regex} candidates as the criterion for FP removal, and retains candidates when confidence $\geq 80$. Double verification applies a second pass to decisions that lean toward FP removal; it is intended to reduce, but cannot eliminate, the risk of removing a true issue.

\subsubsection{L3: LLM-based Semantic Re-evaluation.}

L3 is the stage in which the language model reads the context for violation candidates received through the prompt and finally decides whether each is a false positive or a violation. Receiving the results of L1 and L2 as the prompt input, it performs the final decision using Gemini 2.5 Flash Lite. Fig.~\ref{fig:l3} illustrates the overall flow of the L3 stage.

\begin{figure}[!htbp]
\centering
\caption{L3 pipeline flow.}
\label{fig:l3}
\end{figure}

\paragraph{LLM Decision.}
The model's decision criteria are built into the prompt as follows. The rule statement corresponding to \texttt{rule\_id} is composed of a per-rule decision-use string dictionary and the \texttt{ai\_context} carried over from YAML and similar sources. When necessary, author-prepared requirement-derived guidance retrieved during L2 is placed in the same prompt block. The prompt branches into per-type instructions according to \texttt{pattern\_type}.

The LLM reads the code slice given with this prompt and determines whether it is an actual violation or a false positive; in the \texttt{is\_real\_issue} field of the structured output, if \texttt{true} the violation is retained, and if \texttt{false} it is finally excluded as a false positive. The decision rationale is written in \texttt{description} so that users can verify the evidence when reviewing patches and recommendations, thereby increasing the explainability of the LLM's decisions.

In the prototype, if the confidence of the first response falls in the range $65$--$74$, a re-evaluation prompt is sent once more. This interval was selected heuristically during prototype development and has not yet been justified by a calibration study. We therefore treat it as an implementation setting rather than an empirically optimal threshold; the revision protocol evaluates adjacent windows using reliability diagrams, expected calibration error, Brier score, and the additional-call/FN trade-off. When sufficient context is not provided from L2, \texttt{insufficient\_context} may be set to \texttt{true}, allowing the process to avoid declaring a violation outright on the basis of a short excerpt and instead leave it conservatively or pass it on for further review.

\begin{lstlisting}[language=json,caption={Example output structure of the LLM.},label={lst:output}]
{
  "is_real_issue": "<true | false>",
  "confidence": "<integer 0..100>",
  "description": "<brief rationale, 2-3 sentences>",
  "suggestion": "<one-line remediation>",
  "insufficient_context": "<true | false>"
}
\end{lstlisting}

\paragraph{Final Output.}
Listing~\ref{lst:output} shows the skeleton of the structured final response that the implementation requires from the model. If only free-form description were allowed, it would be difficult to reliably automate report aggregation and the linkage of patch/recommendation wording, and because the decision is hard, the LLM is required to produce the final output in JSON form.

As the final output, \texttt{is\_real\_issue} is the flag that decides whether to keep the given candidate in the final violation set or to remove it from the list, and \texttt{confidence} preserves the numerical strength of the decision even within the same boolean classification, serving as re-review metadata. \texttt{suggestion} fixes the direction of correction in a single line so that it can be carried as-is into a patch-generation prompt or a UI recommendation. As described above, \texttt{description} is the field that records the decision rationale in a human-readable form, and \texttt{insufficient\_context} serves as a signal for downstream processing and display, indicating that the model will not commit to a decision from this call alone because the slice was too short.

\paragraph{Patch Notes and Report Generation.}
After the L3 final decision, the violation list is sorted by severity and confidence, and LLM-based code and document patches are automatically generated. Code patches derive correction examples based on the L2 RAG evidence and the violating code, while document patches provide authoring examples grounded in the KCMVP guidelines for design omissions. Finally, a validation report containing the violation statistics and the LLM's overall assessment (pass likelihood and revision priorities) is produced in markdown and PDF form.

\subsubsection{Traceability Verification.}

In KCMVP certification, not only the source code but also the design specification, configuration management document, test specification, and module must remain mutually consistent. Whether the APIs implemented in the code are specified in the design specification, whether the error codes mentioned in the design specification are defined in the actual source, and whether the public functions are sufficiently exposed in the test specification are items that must be verified at the technical review stage. The traceability verification of this system takes the code summary produced at the preprocessing stage and the document preprocessing results, and performs a cross-comparison across the three document--code axes.

\paragraph{Cross-Comparison Mechanism.}
On the code side, public function declarations of the form \texttt{[return type][function name]([parameters]);} are extracted from header files using regular expressions. \texttt{static} and underscore-prefixed functions are regarded as internal implementations and excluded; only public APIs are taken as traceability targets. From source files, function definitions corresponding to header declarations are extracted to construct declaration--definition pairs, and error-code constants declared by \texttt{\#define} (\texttt{ERR\_*}, \texttt{KCMVP\_ERR\_*}, etc.) are collected separately. In addition, the definitions and call graph of the symbol graph are used as reinforcing means so that the linkage can still be identified even when an API is delegated to another file through a wrapper.

On the document side, function names, error codes, and test items are searched within the design specification and test specification structured at the clause level by the PDF preprocessing. For the design specification, the body and tables of the API-specification clauses are parsed, and the function-name column is matched against the code name list; for the test specification, test-item names and references to test-target APIs are extracted. Based on this, a three-way comparison is performed.

\begin{enumerate}
\item \textbf{Design Specification vs.\ Header:} The list of public APIs extracted from headers and the list of API references extracted from the design specification are cross-compared; header functions not listed in the design specification are recorded as ``undocumented'' candidates, and design-specification APIs not implemented in the header are recorded as ``unimplemented in code'' candidates.

\item \textbf{Design Specification vs.\ Source:} Error codes declared via \texttt{\#define} and the error codes mentioned in the design specification are compared bidirectionally, and error codes existing only in the design specification and those existing only in the code are each classified as violation candidates.

\item \textbf{Test Specification vs.\ Header:} Whether core public functions---such as encryption/decryption, key setting, and initialization---are mentioned as test items in the test specification is checked, and missing items are recorded as violation candidates.
\end{enumerate}

If inconsistencies are found, the corresponding API names, error codes, and test items are recorded as violation candidates and included in the final report.

However, the current traceability-verification implementation has limitations because it relies on regular expressions and name-based matching. Function definitions wrapped by macros, function pointers, and multi-line declarations may be missed during regex extraction, and when function names are listed in tabular form in the design specification or when the code and document use different naming conventions, matching may fail. For this reason, traceability-verification results are reported as review recommendations rather than confirmed violations, so that a human can ultimately make the final judgment.
```

## 제2부. 한국어 번역(학술체)

## 3. 시스템 설계 (System Design)

탐지 정확도를 극대화하는 동시에 오탐(False Positive)을 최소화하기 위해, 본 사전 검증 시스템은 전체 검증 프로세스를 상호 보완적인 세 단계, 즉 규칙 기반 결정론적 탐지(L1), RAG 기반 지침 근거 검색(L2), LLM 기반 최종 판정(L3)으로 세분화한다.

### 3.1 설계 목표 (Design Goals)

본 시스템의 설계는 다음 세 가지 목표를 달성하기 위해 구성되었다.

**목표 1. 높은 Recall 확보.** 본 연구는 패턴 기반의 결정론적 탐지를 통해 높은 recall을 확보하고자 하였다. 특히 missing(필수 패턴의 부재)과 regex(문자열 패턴 일치) 유형을 명시적으로 정의된 규칙으로 적용함으로써, 규칙으로 표현 가능한 위반에 대한 누락을 줄이는 방향의 광범위 탐색(broad-coverage search)을 지향한다.

**목표 2. 오탐(FP) 최소화.** 단순 규칙 기반 탐지는 구조적으로 오탐(유사 패턴, 상수, 시험 코드)을 포함할 수 있으므로, 본 연구는 도메인 특화 필터와 LLM의 최종 판정을 통해 코드와 문서 맥락 및 근거를 함께 검토함으로써 오탐을 최소화하는 것을 목표로 한다.

**목표 3. 근거 기반 코드·문서 동시 검증.** 본 프레임워크는 소스코드(ZIP)와 제출 문서(PDF)를 단일 파이프라인에서 통합 처리하며, L2 단계의 3계층(three-tier) RAG 검색을 통해 탐지된 각 위반 항목에 실제 KCMVP 지침 조항을 자동으로 부착함으로써 검증 결과의 해석 가능성(interpretability)을 확보한다.

### 3.2 전체 시스템 아키텍처 (Overall System Architecture)

전체 파이프라인은 그림 1과 같이 퍼널 구조로 설계되었다. 먼저 소스코드(ZIP)와 제출 문서를 함께 받아 전처리한다. 코드 측에서는 함수·호출 정보를 담은 구조 요약(structural summary)과 파일 간 호출을 잇는 심볼 그래프(symbol graph)를 구축하고, 문서 측에서는 PDF에서 본문 텍스트와 표를 추출한 뒤 목차 등을 활용하여 섹션 리스트(section list)로 구조화한다. 이로써 규칙을 적용할 좌표(파일, 줄, 섹션)를 넓게 확보한다.

이어지는 L1 단계에서는 YAML로 정의된 점검 규칙을 네 가지 패턴 유형으로 적용한다. missing은 필수 요소의 부재를, regex는 문자열 패턴 일치를, semantic은 키워드·문맥 단서를, ast는 구문/구조 단서를 각각 처리한다. 이 단계가 휴리스틱 필터(heuristic filter)를 거치면, 넓게 포착된 오류 의심 목록이 하나의 후보 집합(candidate set)으로 통합된다.

다음 단계에서는 규칙 식별자와 의심 코드/문단(suspect part)을 중심으로 KCMVP 지침 근거를 검색·매칭한다. ChromaDB 등 저장소에 적재된 근거 문서를 활용할 수 있다. 근거 문서는 KCMVP 규격 문서를 주제와 조항 단위로 나누어 마크다운으로 저장한다.

이어서 생성형 모델이 의심 파트, 판정 지시, 근거를 함께 받아 최종적으로 오탐과 실제 위반을 구분한다. 앞 단계에서 넓게 포착된 후보를 근거·맥락 기반 판정으로 정밀하게 줄여 나가는 흐름이 퍼널의 축소 구간에 해당한다. 최종적으로 그 결과는 패치 노트(patch note)와 보고서 같은 산출물로 통합되며, 기각된 항목도 필요하면 후보 이력(candidate history)으로 남겨 추적할 수 있게 한다.

또한 그림에서는 명료성을 위해 생략하였으나, 구현에서 근거 검색은 두 번 호출된다: 한 번은 LLM 판정용 프롬프트를 구성할 때, 또 한 번은 동일 모듈에 의해 최종 위반 목록에 근거 필드를 붙일 때이다. 전자는 판정 맥락에 규격 근거를 주입하기 위함이고, 후자는 보고서와 UI에서 위반별 근거를 확인할 수 있게 하기 위함이다.

표 2는 각 단계의 주요 기능과 역할을 요약한 것이다.

**[그림 1] 전체 파이프라인 구성도(Overall pipeline configuration diagram).** — 상단에 입력으로 Source Code(.zip)와 Documents가 들어가 Preprocessing을 거쳐 Symbol Graph와 Section List를 생성하고, 이어 L1. Static Analysis(missing/regex/semantic/ast → Regex Matching, Heuristic Filtering → Suspected Violation List), L2. Evidence Mapping(RAG)(Rule ID, Target Segment, Violation Evidence ← Reference Documents DB), L3. LLM Re-evaluation(False Positive(FP) / Confirmed Violation)을 거쳐, 최종 산출물로 Remediation Notes와 Pre-validation Report가 나오는 퍼널형 흐름을 도식화한 그림.

**표 2: 제안하는 KCMVP 사전 검증 파이프라인의 단계별 요약.**

| Stage | Analysis method | Main objective |
|---|---|---|
| Preprocessing | Source file normalization; Four-stage AST fallback; Symbol graph construction; Document body, tables, OCR sectioning | Generating file, line, section, and call-relationship coordinates for rule application |
| L1 | Per-pattern-type rule application; Domain-anchor-based candidate refinement | Deterministic primary candidate detection and reduction of obvious false positives |
| L2 | Three-tier RAG retrieval | Attaching KCMVP evidence and decision context for each candidate |
| L3 | Semantic re-evaluation | Distinguishing actual violations from false positives and conservatively removing candidates |
| TRC | Cross-comparison (header API, source definitions, documents) | Traceability inspection across design specifications, code, and test specifications |

### 3.3 검증 파이프라인 단계별 설계

#### 3.3.1 전처리 단계 (Preprocessing Stage)

규칙 엔진과 LLM은 동일 입력에 대해 위반 설명을 일관되게 작성하고, 문제 지점 주변의 코드·문단을 잘라 맥락으로 전달할 수 있도록, 파일 경로, 소스 줄 번호, 문서 섹션, 표처럼 반복 참조 가능한 위치 정보를 필요로 한다. 또한 보안·구현 점검은 단순 문자열 검색만으로는 파악하기 어려우며, 함수가 어디서 호출되고 무엇을 호출하는지와 같은 구조·호출 정보가 있어야만 판단이 더 정확해진다. 따라서 정확도를 높이기 위해, 소스코드를 함수·호출 요약과 함께 줄 단위 텍스트로 변환하고 문서를 섹션 단위 구조를 갖는 본문/표 표현으로 분리하는 전처리 단계를 도입하였다. 구체적으로, 업로드된 ZIP 아카이브와 PDF 문서로부터 구조적 정보를 추출하여 JSON 형태의 분석 아티팩트(analysis artifact)를 생성한다.

**AST 및 심볼 그래프(AST and Symbol Graph).** 추상 구문 트리(Abstract Syntax Tree, AST)는 소스코드의 구문 구조를 트리 형태로 표현한 중간 표현(intermediate representation)으로, 컴파일러 설계 분야에서 구문 분석(parsing) 단계의 표준 출력물이다 [1]. 심볼 그래프는 여러 소스 파일에서 추출한 함수 정의, 함수 호출, 전역 상수 배열 등의 심볼 정보를 노드와 엣지로 연결한 구조화 표현이다.

AST는 한 파일 또는 한 함수 내부에서 연산과 문장이 어떤 구조로 배치되는지에 초점을 두므로 함수 내부의 구현 불변식(implementation invariant)을 검사하는 데 적합하고, 반면 심볼 그래프는 각 함수가 어디에 정의되어 있고 다른 파일의 어떤 함수를 호출하는지를 보여주므로 cross-file zeroization, wrapper 호출과 같은 파일 경계를 넘는 관계를 판단하는 데 사용된다.

C 전처리 단계는 분석 결과에 직접적인 영향을 준다. C/C++에서 표준 전처리기(#define, #include, #ifdef)는 파싱 이전에 토큰 수준에서 소스 구조를 직접 변경할 수 있으며, 이로 인해 원본 소스의 위치 정보와 전처리 이후의 실제 구문 구조가 어긋날 수 있다. C 파서와 규칙 엔진은 단순한 토큰 나열이 아니라 타입, 상수 값, 매크로 확장 결과에 의존하므로, 흩어진 헤더가 적절히 복원되지 않으면 식별자 해석이 어려워지고 잘못된 형태의 노드 구조가 생성될 수 있다.

이에 따라 본 시스템은 gcc -E 전처리, 내부 헤더 추적(internal header tracking), libclang 기반 AST 및 심볼 그래프 구축을 결합하며, 파싱 성공률을 높이기 위해 다음과 같은 다단계 fallback 구조를 채택한다.

1. **1단계. libclang 우선 파싱(libclang-First Parsing):** LLVM libclang을 사용하여 소스 파일의 완전 파싱을 먼저 시도한다. 매크로 확장과 헤더 포함이 내부적으로 처리되므로, 암호모듈 코드에서 흔히 나타나는 복잡한 헤더 의존성이 있어도 구문 트리를 정확하게 구성할 수 있다. 파싱이 성공하면 함수 정의와 호출 관계가 구성되어 심볼 그래프와 함께 AST 요약을 생성한다.

   libclang 파싱 경로에서 시스템은 단순한 호출 정보뿐 아니라 타입 정보와 cross-file 연결 정보까지 수집한다. libclang으로 생성한 심볼 그래프에서 핵심은 Unified Symbol Resolution(USR)에 기반한 연결이다. 같은 이름의 함수가 여러 파일에 존재하거나 헤더 선언과 구현 정의가 분리된 경우, 단순 이름 매칭만으로는 호출 대상이 모호해질 수 있다. libclang은 함수 정의와 호출 표현식의 referenced 커서에서 USR을 얻을 수 있으므로, 본 시스템은 먼저 USR로 호출을 정의 위치에 연결하고, USR이 비어 있는 경우에만 이름 기반 매칭으로 폴백한다. 이 때문에 심볼 그래프의 호출 관계에는 호출 파일, 호출 줄, 피호출 함수명뿐 아니라, 가능한 경우 피호출 함수의 정의 파일과 정의 줄도 함께 포함된다.

   또한 libclang 경로는 typedef 별칭과 정적 상수 배열의 초기화 값을 별도의 증거로 저장한다. typedef는 uint32_t, 함수 포인터 타입, 공개 API 시그니처를 해석하는 데 쓰이고, 정적 상수 배열은 LEA delta, S-box, lookup table, KAT/vector와 같은 공개 상수(public constant)를 비밀 키 후보(candidate secret key)와 구분하는 데 쓰인다. 배열의 경우, 시스템은 VAR_DECL 중 CONSTANTARRAY 타입의 항목을 찾아 초기화 리스트에서 토큰을 추출하고, 변수명·원소 타입·크기·초기값 샘플을 array_inits에 저장한다. 이 값은 이후 하드코딩 키 후보가 실제 비밀 키인지 공개 알고리즘 상수인지 판별하는 핵심 근거가 된다.

2. **2단계. gcc -E + pycparser 전처리(gcc -E + pycparser Preprocessing):** libclang을 사용할 수 없거나 pycparser 기반 fallback이 필요한 경우, 시스템은 먼저 컴파일러의 gcc -E 전처리를 사용하여 매크로가 확장된 C 텍스트를 생성한 뒤 이를 pycparser로 파싱한다.

   이 경우 pycparser 경로의 파싱은 전체 컴파일 환경을 재현하는 것이 아니라, KCMVP 사전 검증에 필요한 함수 정의와 호출 위치를 가능한 한 안정적으로 복원하는 데 초점을 둔다. LLM 판정에서의 오류를 방지하기 위해, 블록 주석과 라인 주석은 제거하되 개행(newline) 수는 보존하여 원본 줄 번호가 어긋나지 않도록 한다. 그 결과, L1이 출력하는 위반 위치와 L3가 받는 코드 슬라이스는 사용자가 제출한 원본 파일 위치를 직접 가리킬 수 있다.

   다음으로, uint32_t, size_t, memset, memcpy처럼 암호 구현에서 자주 등장하는 타입과 표준 함수 선언을 최소 프리앰블(minimal preamble)로 삽입한다. 지역 헤더에 대해서는 #include를 재귀적으로 따라가며, 숫자형 매크로는 enum{NAME = VALUE};로, 단순 별칭 매크로는 typedef로, 함수형 매크로는 int NAME(int arg, ...); 형태의 가짜 선언(fake declaration)으로 변환한다. 이 처리는 대부분의 전처리기 지시문을 제거하면서도, 배열 크기, 타입 이름, 매크로 함수 호출처럼 AST 추출에 필요한 이름 정보를 보존한다.

3. **3단계. 완전 전처리(Full Preprocessing):** 이는 컴파일러 전처리기를 사용할 수 없을 때의 fallback 단계로, 시스템 전처리기 없이도 프로젝트 로컬 헤더에 담긴 타입·이름 정보를 최대한 반영하는 것을 목적으로 한다. 프로젝트 안의 따옴표 #include 지시문만 따라 헤더를 읽은 뒤 주석을 제거하고, 이름 바로 뒤에 괄호가 오는 함수형 매크로(예: #define 항목)만 골라 int name 형태의 가짜 함수 선언으로 변환한다. 이렇게 처리한 고정 선언과 매크로 선언을 앞에 두고, 지시문 줄을 제거한 본문을 붙여 파싱한다.

4. **4단계. 단순 전처리(Simple Preprocessing):** 작업 루트(working root)나 파일 경로가 없거나, 헤더 포함을 적용한 파싱이 실패하면, 시스템은 고정 프리앰블과 소스 내 매크로 선언만으로 재시도한다. 이때 프리앰블과 소스 내 #define 매크로만 처리한다. 3단계에서도 절차가 실패하면, 주석을 제거하고 전처리기 지시문 줄만 빈 줄로 바꾼 본문만으로 파싱을 수행한다.

각 단계에서 파싱이 실패하면 시스템은 자동으로 다음 단계로 전환하며, 프리앰블 삽입으로 인한 줄 번호 차이는 오프셋 보정(offset correction)을 통해 원본 소스코드의 실제 줄 번호로 환산한다. 리스팅 1은 AST 전처리 결과의 JSON 구조 예시를 보여준다.

**Listing 1: AST 전처리 결과의 JSON 스키마.**
```json
{
  "path": "src/lea_key.c",
  "ast": {
    "functions": [
      {
        "name": "lea_encrypt",
        "line": 8, "end_line": 20,
        "calls": [
          {"name":"lea_set_key","line":10},
          {"name":"memset_s","line":19}
        ]
      }
    ],
    "file_calls": [
      {"name":"lea_set_key","line":10},
      {"name":"memset_s","line":19}
    ]
  }
}
```

**문서 섹션 추출(Document Section Extraction).** 문서의 경우, 줄글 본문과 표 두 부분의 텍스트를 모두 올바르게 추출하기 위해 두 가지 라이브러리를 활용하였다. 표는 격자 구조를 복원해야 하므로 pdfplumber [27]를 사용하여 각 페이지 내 표 후보를 탐지하고, 셀 경계에 기반하여 표 데이터를 이차원 배열로 구축한다. 동시에 각 표의 경계 상자(bounding box)를 기록해 두고, PyMuPDF [2]로 본문 텍스트를 추출할 때 그 상자와 면적 기준으로 상당 부분 겹치는 텍스트 블록은 본문 후보에서 제외한다. 이 설계의 목적은 동일한 내용이 연속 본문과 표 구조에 이중으로 남는 것을 방지하고, 표는 구조화된 표현으로, 그 외 서술은 연속 본문으로 각각 유지되도록 역할을 분리하는 데 있다.

본문과 표를 모두 추출한 뒤, 위반 구역을 문단 단위로 표현할 수 있도록 섹션 분리를 수행한다. 섹션 분리는 목차 기반(table-of-contents-based)과 본문 헤더 패턴 기반(body-header-pattern-based)의 두 경로로 진행되며, 목차 기반 경로를 우선한다.

1. **1단계. 목차 우선 경로(Table-of-Contents-First Path):** 페이지별로 이어 붙인 전체 텍스트에서 목차 또는 "Contents"를 탐색한 뒤, "1. 제목… 4", "제N장", "절", "항·페이지"와 같은 항목에 대응하는 정규식으로 각 항목의 식별자, 제목, 문서 내 페이지 번호를 추출한다. 이후 첫 항목 제목에 포함된 단어가 본문에서 재등장하는 물리 페이지를 찾아, 목차에 인쇄된 페이지 번호와 PDF 물리 페이지 간의 오프셋을 산출한다. 각 목차 구간에 대해 오프셋이 보정된 물리 페이지 범위의 본문을 이어 붙이고, 동일 페이지 범위에 속한 표만 해당 섹션에 귀속시킨다. 본문 텍스트에서는 페이지 머리말·꼬리말과, 한 줄 전체가 아라비아 숫자만으로 이루어진 페이지 표기를 제거하여 불필요한 텍스트가 포함되지 않도록 한다.

2. **2단계. 헤더 패턴 경로(Header-Pattern Path):** 목차가 없거나 위 절차가 유효한 섹션을 만들지 못한 경우, 통합 본문 문자열을 줄 단위로 훑으며 계층 제목 후보(hierarchical-heading candidate)를 정규식으로 식별한다. 식별 후, 각 섹션 본문의 시작 부분을 전체 문자열에서 찾아 시작·종료 물리 페이지를 근사한다.

섹션 단위 객체에는 업로드된 문서 경로로 결정되는 문서 유형(document type), 작업 루트 기준 상대 경로 뒤에 섹션 식별자를 이어 붙인 논리 파일 키(logical file key), 섹션 제목, 목차나 헤더 패턴에서 유도한 계층 깊이, 본문이 차지하는 시작 페이지와 끝 페이지, 해당 구간의 본문 텍스트, 그 페이지 범위에 속한 표 목록이 담긴다.

위 두 단계에서 어떤 헤더나 목차도 얻지 못하면 해당 파일 전체를 하나의 섹션으로 묶어 표시한다. 최종적으로 문서 전처리의 단위는 섹션으로 분할되어, L3가 문서 맥락을 재판정할 때 필요한 섹션과 인접 섹션만 받을 수 있게 한다.

텍스트 레이어가 없는 스캔본 PDF는 자동으로 감지되며, Gemini 2.0 Flash Vision OCR 모델 [5]을 사용하여 각 페이지 이미지를 인식하고 텍스트를 추출한다. 이를 통해 스캔본 문서에 대해서도 자동 규칙 검증이 가능해진다.

#### 3.3.2 L1: 규칙 기반 정적 분석 (Rule-based Static Analysis)

L1은 전처리가 넘겨준 산출물을 받아, 저장소에 정의된 점검 규칙을 기계적으로 적용하여 위반 후보 집합을 생성하는 층이다. 그림 2는 L1의 전체 흐름을 나타낸다.

전처리를 통해 공급되는 입력에는, 작업 루트 기준으로 수집된 각 소스 파일의 원문 텍스트, 주석을 제거한 본문, 파일별 AST 요약(함수 정의, 함수 호출 목록 등), 그리고 프로젝트 단위 심볼 그래프(파일 간 호출 관계, zeroization 관련 호출을 정의하는 파일 집합 등)가 포함된다. 규칙 엔진은 이 정보를 바탕으로 YAML에 선언된 조건을 파일마다, 또는 규칙의 scope에 따라 프로젝트 전체에 대해 평가하고, 발견된 사실을 위반 레코드(violation record)로 누적한다.

표 3은 규칙 범주의 세부 분류를 보여준다. 범주는 공통 코드 보안 → 알고리즘별 → 모드별 → 문서 → 추적성 순으로 책임을 분리한다는 기준에 따라 설계되었으며, 룰 스키마는 「2025 암호모듈 제출물 작성 안내서」[7]를 따라 작성하였다.

**[그림 2] L1 파이프라인 흐름(L1 pipeline flow).** — 입력(AST, File, Symbol Graph) → Rule(File Extension, Category, Validation Scope) → Type specific Detection(missing/regex/semantic/ast) → Keyword based Heuristic Filtering → Validation Candidates → L2로 이어지는 흐름을 도식화한 그림. 일부 missing 항목은 Confirmed Violation으로 직접 연결됨.

**표 3: L1 점검 규칙 범주.**

| Category | ID | Main inspection items |
|---|---|---|
| Common security | COM-xxx | Module-wide common security |
| LEA | LEA-xxx | LEA-specific constraints |
| Modes of operation | CBC/CTR/GCM/… | Per-mode-specific constraints |
| Documents | DOC-xxx | Required-section document format |
| Traceability | TRC-xxx | Design–code–test consistency |

**탐지 패턴 유형(Detection Pattern Types).** 표 4는 L1 규칙의 패턴 유형별 탐지 원리와, 산출된 위반이 LLM 기반 재판정 단계(L3)와 어떻게 연결되는지를 개괄한다. 네 유형은 각 규칙이 요구하는 증거의 성격—부재, 문자열, 또는 구문 구조—이 서로 다르기 때문에, 동일한 파이프라인 안에서도 신뢰도와 후속 처리 가중치를 달리 둔다.

1. **missing** — 부재형 규칙은 주석 제거 이후 본문에서 pattern에 기술된 정규식이 전혀 관측되지 않을 때 위반을 산출한다. 적용 단위는 scope에 따라 파일 또는 프로젝트로 달라지며, 후자는 동일 신호가 저장소 어디에서도 한 번도 나타나지 않았다는 사실을 단일 위반으로 압축한다.

2. **regex** — 컴파일된 pattern을 원문 전역에 적용하며, 매칭 구간의 시작·끝 오프셋으로부터 줄 범위를 산출하고 각 매칭을 독립 위반으로 기록한다. 특정 식별자에 대해서는 주변 문맥, 변수명, 주석 행을 제외하는 방식 등으로 휴리스틱 필터링을 적용한다. 객관적인 문자열 수준 일치가 핵심 원리이므로 신뢰도는 상대적으로 높게 유지되나, 심각도에 따라 항목을 L3 재판정으로 분류한다.

3. **semantic** — 의미형 규칙은 pattern을 키워드/트리거 조건으로 다루되, 식별자별로 추가 절차를 덧붙이는 경우를 포함한다. 키워드가 관측되지 않으면 주제 누락 가능성을 반영한 파일 또는 프로젝트 단위 후보 위반을 생성하고, 이후 LLM 기반 의미 재판정 단계에서 검토되어야 함을 나타내는 메타데이터를 기록한다. scope가 명시적으로 파일로 한정되지 않으면, 동일 신호의 반복 발생을 억제하기 위해 집계가 프로젝트 단위로 전환된다. 이 유형은 문맥적 재해석이 필요하므로 L3에서 재판정한다.

4. **ast** — 구문형 규칙은 전체 맥락이 필요한 경우로, 전처리를 통해 생성된 AST의 구조적 속성을 직접 판별하는 전용 검사기(dedicated checker)를 우선 실행한다. 여기서 전용 검사기란 규칙별로 사전 파싱된 AST를 순회하여 위반 여부를 구조적으로 판별하는 전용 함수로, LEA 알고리즘의 20개 규칙에 대해 사전 정의되어 있으며, L3로 보내기 전에 후보를 정제한다. 검사기가 규칙 위반을 탐지하면 플래그를 부여하고, 위반이 발견되지 않으면 해당 규칙을 충족한 것으로 간주하고 점검을 종료한다. 이를 통해 위반이 의심되는 코드 줄을 후보 그룹으로 추출하여 L3 단계에서 재판정한다.

**표 4: 탐지 패턴 유형과 L3 단계 연동 방식.**

| Type | Detection principle | Details | L3 |
|---|---|---|---|
| missing | Absence check | Required pattern omitted | Optional |
| regex | Regular expression | Pattern matching | Optional |
| semantic | keyword + AI | Context-required pattern | Priority |
| ast | AST analysis | Structural inspection | Priority |

**도메인 앵커 기반 후보 정제(Domain-Anchor-based Candidate Refinement).** 본 연구에서 도메인 앵커(domain anchor)는 특정 규칙을 적용하기 전에, 분석 대상 파일 또는 코드 조각이 해당 규칙의 의미 범위(semantic scope)에 속하는지를 판단하기 위한 구조적·문맥적 단서이다. L1 규칙 엔진은 높은 recall을 위해 후보를 넓게 생성하지만, 암호모듈 제출물에는 공개 상수, 시험 벡터, wrapper, 벤치마크, 운용 모드별 파일이 함께 존재하므로 단순 규칙 적용만으로는 오탐이 증가한다. 이에 본 시스템은 규칙 적용 전후에 앵커를 사용하여 후보를 정제한다.

도메인 앵커는 크게 식별 앵커(identification anchor)와 배제 앵커(exclusion anchor)로 나뉜다. 식별 앵커는 특정 코드가 실제 규칙 적용 대상임을 강화하는 증거이다. 예를 들어 LEA 라운드 루프, 라운드 키 배열 접근, ROL/ROR 기반 ARX 연산, delta 상수 참조가 함께 나타나면 해당 파일은 LEA 구현 파일일 가능성이 높다. 반대로 배제 앵커는 표면적으로는 위반처럼 보이지만 실제 검증 맥락에서는 위반이 아닌 대상을 제외하는 증거이다. LEA delta 상수, KAT 입력값, S-box, wrapper의 단순 위임 함수, 벤치마크 전용 고정 평문이 이에 해당한다.

본 시스템의 후보 정제는 두 종류의 앵커를 함께 사용하여, 탐지해야 할 구조 위반은 유지하면서 가치가 낮은 오탐 증거는 줄인다. 이를 통해 L1의 후보 품질이 향상되고, 실제로 문맥 판단이 필요한 후보만 L3로 전달된다.

**YAML 룰셋 구조(YAML Rule-Set Structure).** 리스팅 2는 표 4 패턴을 기반으로 생성된 YAML 기반 룰셋의 예시를 보여준다. 규칙은 id, name, category, scope로 식별·분류되고, 패턴은 pattern_type에 설정하며, 정규식은 pattern에 입력한다. severity와 kcmvp_ref는 심각도 등급화와 근거 인용을 위한 부가 정보이다.

**Listing 2: COM-001 규칙의 YAML 구조 요약.**
```yaml
- id: COM-001
  name: "Residual data clearing (zeroization)"
  category: common
  scope: project
  pattern_type: "missing"
  pattern: "<safe zeroization API names>"
  severity: high
  kcmvp_ref: "KS X ISO/IEC 19790:2015 ..."
```

#### 3.3.3 L2: RAG 기반 근거 매칭 (RAG-based Evidence Matching)

L2는 근거 검색과 입력 구성을 통해 맥락을 공급하는 단계이다. 그림 3은 L2 단계의 전체 흐름을 나타낸다. L1에서 식별된 위반 후보는 개별 인스턴스로 전달되며, 각 항목에 대해 판정에 필요한 최소 메타데이터—규칙 식별자, 패턴 유형, 파일 및 줄 위치, 위반 설명 등—를 정리한다. 동시에 해당 위치 주변의 소스(또는 문서) 구간을 코드/문서 슬라이스로 추출하여, 맥락을 유지하면서도 모델 입력 토큰을 줄인다.

다음으로, rule id를 키로 매칭하여 DB에 저장된 KCMVP 관련 지침·기술 자료에서 근거 문서를 첨부한다. 최종적으로 수집된 슬라이스, 위반 설명, 검색된 근거를 헤더, 시스템 역할(system role), 출력 형식 지시와 함께 하나의 프롬프트로 묶어 언어 모델에 제출하고, 그 응답을 L3로 넘긴다.

**[그림 3] L2 파이프라인 흐름(L2 pipeline flow).** — L1 Validation Candidates → Code Chunking(Pattern type, File/Line, Violation Description, Rule ID) → Prompt Construction(Header, System role, Context: Code Non-compliant Segments, Violation Description, Enforced \<JSON\> Output → Validation Criteria) → L3로 이어지며, 하단에 DB와 Direct Mapping / Chroma DB / TF-IDF의 3계층 검색이 Validation Criteria로 연결되는 흐름을 도식화한 그림.

**판정용 맥락 발췌(Decision-Use Context Exception).** 전체 원문을 그대로 언어 모델에 입력하면 입력 길이에 따라 비용과 지연(latency)이 커지고, 관련 없는 문장이 많아질수록 주의(attention)가 분산되어 판정 품질이 저하될 수 있다. 따라서 판단에 필요한 최소한의 연속 구간(contiguous segment)만 발췌한다. 발췌 폭은 패턴 유형과 문서 구조에 맞게 달리하여, 토큰 예산(token budget) 내에서 호출 관계, 주변 조건, 인접 절 간의 흐름과 같은 국소 맥락을 끊김 없이 보존한다.

1. **코드 슬라이싱(Code Slicing).** 파일 경로와 줄 위치를 기준으로 해당 지점을 중심으로 한 연속 소스 줄 블록을 잘라 판정용 스니펫을 구성한다. 전후 윈도 크기는 패턴 유형별로 달리하여, regex 위반은 좁은 맥락을, semantic/구문형 후보는 비교적 넓은 맥락을 사용함으로써 주변 선언과 호출 관계까지 함께 검토할 수 있게 한다.

2. **문서 발췌(Document Excerption).** 문서 재판정의 경우, 시스템은 전처리로 얻은 절 단위 구조를 활용하되 특정 절만 보여주는 데 그치지 않고, 동일 문서 유형에 속한 여러 절을 묶어 하나의 맥락 덩어리를 만든다. 이는 위반으로 표시된 절에 키워드가 없더라도, 동등한 내용이 다른 절에 서술되어 있는지를 함께 검토하려는 의도이다. 다만 각 절의 본문이 매우 길 수 있으므로, 절마다 앞부분만 잘라 한 절이 입력 전체를 차지하지 않게 하고, 여러 절을 이어 붙일 때에는 결합 문자열 전체에 상한을 두어 모델이 한 번에 처리할 분량과 비용을 통제한다.

**3계층 검색 구조(Three-Tier Retrieval Structure).** 근거 검색은 세 단계로 나뉘며, 가장 신뢰할 만한 경로를 먼저 시도한다. 규칙이 공식 지침 원문과 직접 연결된 경우를 출처를 명확히 하기 위해 최우선으로 두고, 그 결과가 없거나 부족할 때만 의미 기반 검색으로 관련 구절을 보강하거나 대체한다. 그래도 공백이 남으면, 키워드 및 통계적 유사도로 더 넓은 문서 집합을 훑는 경로로 폴백하여, 최종적으로 근거 공백을 줄이는 데 초점을 둔다.

1. **Direct 매핑(1계층):** 룰셋 식별자(id)에 대응하여, 그 관계에 따라 지정된 마크다운 지침을 로드한다. 지침은 암호모듈 지침 문서 [7, 22, 21]의 항목을 분절하여 근거 후보 청크(candidate evidence chunk)로 구성하였다. 절 제목이 요구사항, 위반 양상, 해설 등 판정에 직접 유용한 의미를 드러내는 경우 우선순위를 부여하여 앞쪽에 배치하고, 나머지 절은 후순위로 이어 붙이며, 최종적으로 반환할 청크 수는 상한에 맞춰 절단한다. 이는 검토자가 규칙과 공식 문서를 명시적으로 연결했음을 전제하므로, 출처의 특정성과 재현성을 높인다.

2. **ChromaDB 벡터 검색(2계층):** 지침 마크다운을 절/문단 단위로 벡터 저장소(ChromaDB)에 나누어 두고, 각 조각을 임베딩 모델로 실수 벡터에 올린 뒤, 질의 문장도 같은 공간에 투영하여 의미론적으로 유사한 조각을 선택하는 경로이다. 특정 지침 절이 이미 Direct 매핑으로 확보된 경우에는 기존 목록을 대체하지 않고, 동일 질의로 벡터 검색을 수행하여 출처가 다른 소수의 조각만 덧붙여 근거의 폭을 넓힌다. Direct 매핑이 비어 있는 경우에는 조항 식별자 등의 메타데이터를 필터로 삼아 질의와 의미적으로 가까운 청크를 찾아 주된 반환 결과로 삼는다. 이를 통해 규칙-문서의 명시적 연결을 깨뜨리지 않으면서 의미 있는 근거를 보강하거나 대체한다.

3. **TF-IDF 키워드 폴백(3계층):** TF-IDF 경로는 각 청크를 용어 빈도(term frequency)와 문서 집합 전체에서의 희소성을 반영한 유사도 점수로 순위화하여 상위 소수(top-k)만 반환한다. 질의는 호출 시 주어지거나 규칙 매핑에 저장된 검색 문구를 사용한다. 이 경로는 벡터 검색이 비활성이거나 유효한 결과를 내지 못할 때 최후의 수단으로 호출된다. 의미적 일치까지 보장하지는 않으나, 광범위한 문서 집합에서 어휘적으로 근접한 절을 신속히 건져 근거 공백을 줄이는 보수적 안전망(conservative safety net) 역할을 한다.

위와 같이 선별·정렬된 근거 청크는 참고 지침 블록으로 프롬프트에 주입되며, 최종 보고 JSON의 evidence 필드에도 요약 형태로 추가되어 근거를 제공한다.

**프롬프트 구성(Prompt Construction).** 위의 발췌와 근거 검색을 거친 뒤 프롬프트를 구성한다. 본 시스템의 프롬프트 설계는 단순한 역할 지시와 코드 삽입 구조를 넘어, 판정 정확도와 오탐 억제를 동시에 달성하기 위해 3개 계층(tier)에 걸쳐 8가지 기법을 결합한 계층적 하이브리드 프롬프팅(Hierarchical Hybrid Prompting) 아키텍처를 채택한다. 1계층(Tier 1)은 모든 후보에 공통으로 적용되는 판단 프레임을 설정하고, 2계층(Tier 2)은 규칙의 특성에 따라 선택적으로 판단을 실행하며, 3계층(Tier 3)은 모델 출력에 적용되는 후처리 안전망이다. 각 기법의 구성은 표 5와 같다.

1계층은 판단 관점을 고정하는 프레임 역할을 한다. Persona Prompting은 모델에 "KCMVP 암호모듈 보안 검토 전문가" 역할을 부여하여, 일반적인 보안 지식이 아니라 KCMVP 규칙에 따라 판정하도록 한다. RAG Guideline Injection은 L2 근거 검색에서 수집한 KCMVP 지침 발췌를 프롬프트 앞부분에 삽입하여 규칙 출처와 판정 기준을 명시한다. GCFS(Global Code Flow Context Injection)는 심볼 그래프의 함수 정의와 호출 관계를 파일별 키 생명주기 흐름(key-lifecycle flow)으로 압축하여, 단일 스니펫만으로는 보이지 않는 프로젝트 전체의 키 생성–사용–제거 흐름을 모델에 전달한다.

2계층은 각 규칙의 특성에 따라 선택적으로 적용된다. Few-shot 예시는 문맥적으로 파악하기 어려운 18개 규칙에 대해 위반·정상·FP 코드 예시를 제시하여 경계 케이스(boundary-case) 판정 기준을 구체적인 코드 패턴으로 보여준다. Structured evidence는 AST 검사기와 심볼 그래프에 의존하는 규칙에 대해 타입 별칭, 배열 초기화 값, 함수 파라미터, 호출 경로를 명시적으로 삽입한다. CoT(Chain-of-Thought)는 LEA 라운드 키 인덱스 경계나 CBC/CTR/GCM 초기화 순서처럼 다단계 문맥 이해가 핵심인 23개 규칙에 적용되며, 단계적 추론 순서를 명시하여 모델의 추론 사슬(chain of reasoning)을 유도한다. 확신도 요청(confidence request)은 모든 후보에 대해 confidence 필드에 0~100 정수를 요구하며, 이 값은 3계층 후처리에 활용된다.

3계층은 판정 결과의 안전성을 검증하는 후처리 계층이다. 비대칭 FP 임계값(asymmetric FP threshold)은 ast/semantic 후보에 대해 confidence < 25, regex 후보에 대해 confidence < 40을 FP 제거 기준으로 설정하고, confidence ≥ 80인 경우에는 모델 판정과 무관하게 위반을 강제 유지하여 recall을 보호한다. 이중 검증(Double verification)은 FP 제거 방향으로 기우는 판정에 대해 "시니어 감사자(senior auditor)" 페르소나로 2차 검증을 수행하여, 실제 위반이 오탐으로 잘못 제거되는 FN 위험을 차단한다.

**표 5: 계층적 하이브리드 프롬프팅 아키텍처 구성.**

| Tier | Technique | Role |
|---|---|---|
| Judgment-frame setting | Persona Prompting | Assigns the role of a KCMVP reviewer |
| | RAG Guideline | Injects specification evidence into the prompt |
| | GCFS | Summarizes the project-wide key lifecycle |
| Per-rule judgment execution | Few-shot examples | Provides violation, normal, and FP decision examples |
| | Structured evidence | Makes type, array, and call-path evidence explicit |
| | Chain-of-Thought (CoT) | Guides stepwise reasoning |
| | Confidence request | Supports post-processing using a 0–100 confidence score |
| Result-safety verification | Asymmetric FP threshold | Imposes a higher confirmation cost for false-positive removal |
| | Double verification | Blocks FN risk through independent secondary verification |
| | Rejudge | Re-reviews low-confidence violations |

#### 3.3.4 L3: LLM 기반 의미론적 재판정 (LLM-based Semantic Re-evaluation)

L3은 언어 모델이 프롬프트를 통해 받은 위반 후보의 맥락을 읽고, 각 후보가 오탐인지 위반인지 최종 판정하는 단계이다. L1과 L2의 결과를 프롬프트 입력으로 받아, Gemini 2.5 Flash Lite를 사용하여 최종 판정을 수행한다. 그림 4는 L3 단계의 전체 흐름을 나타낸다.

**LLM 판정(LLM Decision).** 모델의 판정 기준은 다음과 같이 프롬프트에 내장된다. rule_id에 대응하는 규칙 서술은 규칙별 판정용 문자열 사전과 YAML 등에서 넘어온 ai_context(규정 상세)로 구성되며, 필요 시 L2(근거 검색) 단계에서 RAG로 가져온 KCMVP 지침 발췌가 같은 프롬프트 블록에 실린다. 프롬프트는 pattern_type에 따라 유형별 지침으로 분기되어, 존재형(regex 등)과 부재형(semantic, ast)마다 오탐/위반 조건과 확신도 하한이 다르도록 설계된다.

LLM은 이 프롬프트와 함께 주어진 코드 슬라이스를 읽고 실제 위반인지 오탐인지 판별한다. 구조화 출력(structured output)의 is_real_issue 필드가 true이면 위반을 유지하고, false이면 오탐으로 최종 배제한다. 판정 근거는 description에 작성되어, 사용자가 패치·권고를 검토할 때 근거를 확인할 수 있게 함으로써 LLM 판정의 설명 가능성을 높인다.

또한 1차 응답의 confidence가 대략 65~74 범위에 걸치는 경우, 재판정 프롬프트를 한 번 더 보내 이유와 점수를 재정리한다. L2에서 충분한 맥락이 제공되지 않은 경우에는 insufficient_context를 true로 설정할 수 있으며, 이를 통해 짧은 발췌만으로 위반을 단정하지 않고 보수적으로 남기거나 후속 검토로 넘긴다.

**[그림 4] L3 파이프라인 흐름(L3 pipeline flow).** — L2 Prompt(Persona, Context, Violation Description, Validation Criteria)로 구성된 Violation Candidates가 AI를 거쳐 Final Determination 단계에서 Status(True Positive(TP)/False Positive(FP)/Insufficient_context)로 분류되고, Confidence Estimation → Confidence Mapping → Dual Validation(2차 검증) → 재평가(Re-evaluation)를 거쳐, 결과적으로 TP는 유지·FP는 제외(Exclusion)되며 최종 산출물(Report, Patch Notes)로 이어지는 흐름을 도식화한 그림.

**최종 출력(Final Output).** 리스팅 3은 구현체가 모델에게 요구하는 구조화된 최종 응답의 뼈대를 보여준다. 자유 서술(free-form description)만 허용하면 보고서 집계와 패치/권고 문구 연계를 안정적으로 자동화하기 어렵고 판정이 까다로우므로, 최종 출력은 JSON 형식으로 LLM에게 강제한다.

최종 출력에서 is_real_issue는 해당 후보를 최종 위반 집합에 남길지 목록에서 제거할지를 결정하는 플래그이고, confidence는 동일 불리언 분류 안에서도 판단의 수치적 강도를 보존하여 재검토 메타데이터로 쓰인다. suggestion은 수정 방향을 한 줄로 고정하여 패치 생성 프롬프트나 UI 권고에 그대로 실을 수 있게 한다. 앞서 서술한 대로 description은 판정 근거를 사람이 읽을 수 있게 기록하는 필드이며, insufficient_context는 슬라이스가 너무 짧아 이번 호출만으로 판단을 확정하지 않겠다는 신호로서 후속 처리·표시에 쓰인다.

**Listing 3: LLM 출력 구조 예시.**
```json
{
  "is_real_issue": "<true | false>",
  "confidence": "<integer 0..100>",
  "description": "<brief rationale, 2-3 sentences>",
  "suggestion": "<one-line remediation>",
  "insufficient_context": "<true | false>"
}
```

**패치 노트 및 보고서 작성(Patch Notes and Report Generation).** L3 최종 판정 후, 위반 목록을 심각도와 확신도 순으로 정렬하고 LLM 기반의 코드 및 문서 패치를 자동 생성한다. 코드 패치는 L2의 RAG 근거와 위반 코드를 바탕으로 수정 예시를 도출하며, 문서 패치는 설계 누락 항목에 대해 KCMVP 지침 기반의 작성 예시를 제공한다. 최종적으로 위반 통계와 LLM의 종합 평가(합격 가능성 및 수정 우선순위)가 포함된 검증 보고서를 마크다운 및 PDF 형태로 산출한다.

**추적성 검증(Traceability Verification).** KCMVP 인증에서는 소스코드뿐 아니라 설계서, 형상관리 문서, 시험서, 모듈이 서로 일관성을 유지해야 한다. 코드에 구현된 API가 설계서에 명시되어 있는지, 설계서에 언급된 에러 코드가 실제 소스에 정의되어 있는지, 공개 함수가 시험서에 충분히 드러나는지는 기술 검토 단계에서 반드시 확인해야 하는 항목이다. 본 시스템의 추적성 검증은 전처리 단계에서 생성된 코드 요약과 문서 전처리 결과를 입력받아, 설계서–코드–시험서의 세 축 간 교차 대조(cross-comparison)를 수행한다.

**교차 대조 메커니즘(Cross-Comparison Mechanism).** 코드 측에서는 헤더 파일에서 `[반환타입][함수명]([파라미터]);` 형태의 공개 함수 선언을 정규식으로 추출한다. static 및 밑줄(`_`) 접두 함수는 내부 구현으로 간주하여 제외하고, 공개 API만 추적 대상으로 삼는다. 소스 파일에서는 헤더 선언에 대응하는 함수 정의를 추출하여 선언-정의 쌍(declaration–definition pair)을 구성하고, #define으로 선언된 에러 코드 상수(ERR_*, KCMVP_ERR_* 등)를 별도로 수집한다. 또한 심볼 그래프의 정의와 호출 그래프를 보강 수단으로 활용하여, API가 wrapper를 통해 다른 파일에 위임된 경우에도 연결 관계를 식별할 수 있게 한다.

문서 측에서는 PDF 전처리로 절 단위로 구조화된 설계서·시험서 안에서 함수명, 에러 코드, 시험 항목을 탐색한다. 설계서의 경우 API 명세 절의 본문과 표를 파싱하여 함수명 컬럼을 코드 이름 목록과 대조하고, 시험서의 경우 시험 항목명과 시험 대상 API 언급을 추출한다. 이를 바탕으로 세 갈래 대조(three-way comparison)를 수행한다.

1. **설계서 대 헤더(Design Specification vs. Header):** 헤더에서 추출한 공개 API 목록과 설계서에서 추출한 API 언급 목록을 교차 대조하여, 설계서에 기재되지 않은 헤더 함수는 "문서 미기재(undocumented)" 후보로, 헤더에 구현되지 않은 설계서 API는 "코드 미구현(unimplemented in code)" 후보로 기록한다.

2. **설계서 대 소스(Design Specification vs. Source):** #define으로 선언된 에러 코드와 설계서에 언급된 에러 코드를 양방향으로 비교하여, 설계서에만 존재하는 에러 코드와 코드에만 존재하는 에러 코드를 각각 위반 후보로 분류한다.

3. **시험서 대 헤더(Test Specification vs. Header):** 암복호화, 키 설정, 초기화 등 핵심 공개 함수가 시험서의 시험 항목으로 언급되었는지 확인하고, 누락된 항목을 위반 후보로 기록한다.

불일치가 발견되면 해당 API명, 에러 코드, 시험 항목을 위반 후보로 기록하여 최종 보고서에 포함한다.

다만 현재의 추적성 검증 구현은 정규식과 명칭 기반 매칭에 의존하므로 한계가 있다. 매크로로 감싼 함수 정의, 함수 포인터, 다중 행 선언은 정규식 추출 과정에서 누락될 수 있고, 설계서에서 함수명이 표 형태로 기재되거나 코드와 문서가 서로 다른 명명 규칙을 사용할 경우 매칭에 실패할 수 있다. 이러한 이유로 추적성 검증 결과는 확정 위반이 아니라 검토 권고(review recommendation) 형태로 보고하여, 사람이 최종 판단을 내릴 수 있도록 한다.

## 제3부. 최신 원고 변경 추적

아래 항목은 `source_lncs/03system_design.tex`과 최신 `overleaf/03system_design.tex` 사이의 모든 의미 변경을 나타낸다. 기존 문장은 취소선, 최신 문장은 빨간색으로 표시한다. 한국어는 최신 문장의 의미를 학술체로 번역한다.

### 변경 3-1. L1 자산 표 캡션

~~L1 inspection-rule categories.~~

<span style="color:red">System rule-asset domains and execution paths.</span>

한국어 번역: 시스템 규칙 자산의 영역과 실행 경로를 제시한다.

### 변경 3-2. 문서 및 추적성 규칙의 실행 경로

~~Documents & DOC-xxx & Required-section document format~~
<span style="color:red">Documents & DOC-xxx & Separate document-validation service</span>

한국어 번역: 문서 규칙(DOC-xxx)은 별도의 문서 검증 서비스에서 실행한다.

~~Traceability & TRC-xxx & Design--code--test consistency~~
<span style="color:red">Traceability & TRC-xxx & Separate design--code--test traceability service</span>

한국어 번역: 추적성 규칙(TRC-xxx)은 별도의 설계서--코드--시험서 추적성 서비스에서 실행한다.

### 변경 3-3. 규칙 자산 수와 적용 범위

~~Table 2 shows the detailed classification of rule categories. The categories were designed on the basis of separating responsibilities in the order common code security → per-algorithm → per-mode → documents → traceability, and the rule schema was written following the 2025 Cryptographic Module Submission Authoring Guide.~~

<span style="color:red">Table 2 shows the system asset domains. The 92 code-oriented assets execute in L1, 65 document assets execute in the document-validation service, and four traceability assets use a separate custom schema and service. The four pattern types below apply to the 157 code and document assets, not to the four traceability assets.</span>

한국어 번역: 표 2는 시스템 자산의 영역을 제시한다. 코드 지향 자산 92개는 L1에서 실행하고, 문서 자산 65개는 문서 검증 서비스에서 실행하며, 추적성 자산 4개는 별도의 사용자 정의 스키마와 서비스를 사용한다. 아래의 네 가지 패턴 유형은 코드 및 문서 자산 157개에 적용하며, 추적성 자산 4개에는 적용하지 않는다.

### 변경 3-4. AST 전용 검사기 수

~~Here, a dedicated checker is a specialized function that traverses the pre-parsed AST per rule and structurally judges whether the list is violated; these are predefined for the 20 rules of the LEA algorithm and refine the candidates before sending them to L3.~~

<span style="color:red">Dedicated checker mappings currently cover 25 LEA rule identifiers through 24 distinct checker implementations, because one rule identifier shares an implementation.</span>

한국어 번역: 현재 전용 검사기 매핑은 24개의 고유 검사기 구현을 통해 25개의 LEA 규칙 식별자를 포괄하며, 이는 하나의 규칙 식별자가 구현을 공유하기 때문이다.

### 변경 3-5. 3계층 검색 근거의 지위

~~Evidence retrieval is divided into three stages, with the most reliable path attempted first. The case in which a rule is directly linked to the original text of an official guideline is prioritized highest in order to clarify provenance; only when that result is absent or insufficient does semantic search reinforce or replace it with related passages. If gaps still remain, the procedure falls back to a path that sweeps a broader document set by keyword and statistical similarity, ultimately focused on reducing evidence gaps.~~

<span style="color:red">Evidence retrieval is divided into three stages, with a direct mapping attempted first. The current corpus contains author-prepared guidance and mappings derived from the cited requirements; it must not be interpreted as a verbatim or authoritative reproduction of an official guideline. When a direct mapping is absent or insufficient, semantic search retrieves related passages, followed by a broader keyword and similarity search. Retrieved passages are supporting context rather than independent validation.</span>

한국어 번역: 근거 검색은 세 단계로 구분하며 직접 매핑을 먼저 시도한다. 현재 코퍼스는 인용한 요구사항으로부터 도출하여 저자가 작성한 지침 및 매핑으로 구성하며, 공식 지침을 그대로 재현한 자료 또는 권위 있는 원문으로 해석해서는 안 된다. 직접 매핑이 없거나 불충분한 경우 의미 검색을 통해 관련 구절을 검색하고, 이후 더 넓은 키워드 및 유사도 검색을 수행한다. 검색한 구절은 독립적인 검증 결과가 아니라 판정을 지원하는 맥락으로 사용한다.

### 변경 3-6. Direct Mapping의 지위

~~Corresponding to the rule-set identifier (`id`), the designated markdown guideline is loaded according to that relationship. The guideline was constructed as candidate evidence chunks by segmenting items based on the cryptographic-module guideline documents. When a clause title directly reveals meaning useful for the decision—such as requirements, violation patterns, or commentary—priority is assigned to place it at the front, and the remaining clauses are appended at lower priority; finally, the number of chunks to be returned is truncated to a cap. Because this presupposes that the reviewer has explicitly linked the rule with the official document, the specificity and reproducibility of the sources are enhanced.~~

<span style="color:red">Corresponding to the rule-set identifier (`id`), designated author-prepared guidance is loaded. It was constructed as candidate evidence chunks derived from cited cryptographic-module documents. An explicit author-maintained rule--guidance link makes the mapping inspectable, but it is neither an independent validation nor an authoritative reproduction of the source.</span>

한국어 번역: 룰셋 식별자(`id`)에 대응하여 저자가 작성한 지정 지침을 불러온다. 해당 지침은 인용한 암호모듈 문서로부터 도출한 근거 후보 청크로 구성한다. 저자가 명시적으로 유지·관리하는 규칙--지침 연결을 통해 매핑을 점검할 수 있으나, 이를 독립적인 검증이나 권위 있는 원문의 재현으로 간주하지 않는다.

### 변경 3-7. 이중 검증의 효과 표현

~~Blocks FN risk through independent secondary verification~~

<span style="color:red">Provides a second-pass review intended to reduce FN risk</span>

한국어 번역: 미탐(FN) 위험을 줄이기 위한 2차 검토를 제공한다.

### 변경 3-8. Tier 1 설명

~~Tier 1 serves as a frame that fixes the judgment perspective. Persona Prompting assigns the model the role of a “KCMVP cryptographic-module security review expert” so that decisions are made not on general security knowledge but according to KCMVP rules. RAG Guideline Injection inserts the KCMVP guideline excerpts collected during the L2 evidence retrieval into the front part of the prompt, making the rule provenance and decision criteria explicit. GCFS (Global Code Flow Context Injection) compresses the function definitions and call relationships of the symbol graph into a per-file key-lifecycle flow, conveying to the model the project-wide key creation -- use -- destruction flow that is not visible from a single snippet alone.~~

<span style="color:red">Tier 1 serves as a judgment frame. Persona Prompting assigns the model the role of a “KCMVP cryptographic-module security review expert.” RAG injection places retrieved author-prepared, requirement-derived guidance into the prompt as supporting context. GCFS (Global Code Flow Context Injection) compresses the function definitions and call relationships of the symbol graph into a per-file key-lifecycle flow, conveying to the model the project-wide key creation -- use -- destruction flow that is not visible from a single snippet alone.</span>

한국어 번역: Tier 1은 판정 프레임으로 기능한다. 페르소나 프롬프팅은 모델에 “KCMVP 암호모듈 보안 검토 전문가”의 역할을 부여한다. RAG 주입은 요구사항으로부터 도출하여 저자가 작성한 지침을 판정 지원 맥락으로 프롬프트에 배치한다. GCFS는 심볼 그래프의 함수 정의와 호출 관계를 파일별 키 생명주기 흐름으로 압축하여 단일 스니펫만으로 확인하기 어려운 프로젝트 전반의 키 생성--사용--제거 흐름을 모델에 전달한다.

### 변경 3-9. Tier 3의 보수적 표현

~~Tier 3 is the post-processing layer that verifies the safety of the decision results. The asymmetric FP threshold sets confidence < 25 for ast/semantic candidates and confidence < 40 for regex candidates as the criterion for FP removal, and forces the violation to be retained regardless of the model's decision when confidence ≥ 80, thereby protecting recall. Double verification performs secondary verification for decisions that lean toward FP removal, using a “senior auditor” persona, thereby blocking the FN risk that an actual violation is mistakenly removed as a false positive.~~

<span style="color:red">Tier 3 is a conservative post-processing layer. The asymmetric FP threshold sets confidence < 25 for ast/semantic candidates and confidence < 40 for regex candidates as the criterion for FP removal, and retains candidates when confidence ≥ 80. Double verification applies a second pass to decisions that lean toward FP removal; it is intended to reduce, but cannot eliminate, the risk of removing a true issue.</span>

한국어 번역: Tier 3은 보수적인 후처리 계층이다. 비대칭 오탐 임계값은 `ast`/`semantic` 후보의 확신도가 25 미만이고 `regex` 후보의 확신도가 40 미만인 경우를 오탐 제거 기준으로 설정하며, 확신도가 80 이상인 후보는 유지한다. 이중 검증은 오탐 제거 방향의 판정에 2차 검토를 적용하며, 실제 위반을 제거할 위험을 줄이려는 목적을 가지지만 해당 위험을 완전히 제거하지는 못한다.

### 변경 3-10. LLM 판정 기준의 근거 표현

~~The model's decision criteria are built into the prompt as follows. The rule statement corresponding to `rule_id` is composed of a per-rule decision-use string dictionary and the `ai_context` (specification details) carried over from YAML and similar sources, and when necessary, KCMVP guideline excerpts retrieved by RAG during the L2 (evidence retrieval) stage are placed in the same prompt block. The prompt branches into per-type instructions according to `pattern_type`, designed so that the false-positive/violation conditions and the lower bound of confidence differ between absence types (`semantic`, `ast`) and presence types (`regex`, etc.).~~

<span style="color:red">The model's decision criteria are built into the prompt as follows. The rule statement corresponding to `rule_id` is composed of a per-rule decision-use string dictionary and the `ai_context` carried over from YAML and similar sources. When necessary, author-prepared requirement-derived guidance retrieved during L2 is placed in the same prompt block. The prompt branches into per-type instructions according to `pattern_type`.</span>

한국어 번역: 모델의 판정 기준은 다음과 같이 프롬프트에 포함한다. `rule_id`에 대응하는 규칙 서술은 규칙별 판정용 문자열 사전과 YAML 등의 `ai_context`로 구성한다. 필요한 경우 L2에서 검색한 요구사항 기반의 저자 작성 지침을 동일한 프롬프트 블록에 배치한다. 프롬프트는 `pattern_type`에 따라 유형별 지침으로 분기한다.

### 변경 3-11. 65--74 재판정 구간

~~In addition, if the confidence of the first response falls roughly in the range 65--74, a re-evaluation prompt is sent once more to reorganize the reasons and the score.~~

<span style="color:red">In the prototype, if the confidence of the first response falls in the range 65--74, a re-evaluation prompt is sent once more. This interval was selected heuristically during prototype development and has not yet been justified by a calibration study. We therefore treat it as an implementation setting rather than an empirically optimal threshold; the revision protocol evaluates adjacent windows using reliability diagrams, expected calibration error, Brier score, and the additional-call/FN trade-off.</span>

한국어 번역: 프로토타입에서는 1차 응답의 확신도가 65--74 구간에 해당할 경우 재판정 프롬프트를 한 차례 더 전송한다. 이 구간은 프로토타입 개발 과정에서 휴리스틱하게 선택하였으며 보정 연구를 통해 아직 정당화하지 않았다. 따라서 이를 실증적으로 최적인 임계값이 아니라 구현 설정으로 간주하며, 수정 실험 프로토콜에서는 신뢰도 다이어그램, 기대 보정 오차, Brier 점수 및 추가 호출과 미탐(FN) 간의 상충관계를 이용하여 인접 구간을 평가한다.

## 완전성 감사 결과

| 감사 항목 | LaTeX 원문 | Markdown 영문 원문층 | 결과 |
|---|---:|---:|---|
| 캡션(표·그림·리스팅) | 8 | 8 | 일치 |
| 표 환경 | 4 | 4 | 일치 |
| 리스팅 환경 | 3 | 3 | 일치 |
| 열거 항목 | 18 | 18 | 일치 |
| 그림 환경 | 4 | 4 | 일치(이미지 명령만 제외) |
| 절·소절·문단 표제 | 20 | 20 | 일치 |

영문 원문층을 다시 추출한 뒤 최신 LaTeX에서 `includegraphics` 행만 제거한 결과와 바이트 단위로 비교하였으며 차이가 없음을 확인하였다. 변경 추적층은 구 원고와 최신 원고 간 통합 diff의 모든 의미 변경을 포함한다.

---

---

# 4. Prototype Implementation / 프로토타입 구현

## 4.1. Implementation Environment / 구현 환경

This interface is designed with the purpose of enabling users to clearly specify their analysis settings and submission materials and then review the entire pipeline's outputs without missing anything. That is, the interface treats code and submitted documents as equal validation targets; separates the roles of navigation, body, and violation information so that users can quickly verify and judge the mechanical detection results in context; and has the final report reveal the summary and details sequentially, with an emphasis on reducing the cognitive load that may arise during pre-conformance inspection and on improving readability for the user.

본 인터페이스는 사용자가 분석 설정과 제출 자료를 명확하게 지정하고 전체 파이프라인의 출력을 누락 없이 검토하도록 설계한다. 즉, 코드와 제출 문서를 동등한 검증 대상으로 취급하고, 탐색·본문·위반 정보의 역할을 분리하여 기계적 탐지 결과를 문맥에서 신속하게 검토하도록 하며, 최종 보고서는 요약과 세부 정보를 순차적으로 제시한다. 이를 통해 사전 적합성 검사에서 발생하는 인지 부하를 줄이고 가독성을 향상한다.

## 4.2. Prototype Screen Layout / 프로토타입 화면 구성

### Initial Screen / 초기 화면

Fig. 1 shows the initial screen of this pre-certification tool. The user can specify analysis conditions---such as the security level, product category, cryptographic algorithm, and mode of operation---matching the conditions of the actual test application, then submit the source code via a GitHub URL or a ZIP archive, and additionally upload PDFs by document type, including the design specification, configuration management, and test specification.

그림 1은 사전 인증 도구의 초기 화면을 나타낸다. 사용자는 실제 시험 신청 조건에 부합하는 보안 수준, 제품 유형, 암호 알고리즘 및 운용 모드 등의 분석 조건을 지정하고, GitHub URL 또는 ZIP 아카이브로 소스 코드를 제출하며, 설계 명세서·형상관리 문서·시험 명세서 등의 PDF를 문서 유형별로 추가 업로드한다.

**Figure 1. Initial-screen layout. / 그림 1. 초기 화면 구성.**

### Main Screen / 메인 화면

Fig. 2 and Fig. 3 show the main verification screen that compares code and violations after the analysis is complete. The review screen of this system adopts a three-pane layout. The layout is arranged so that the user naturally proceeds in the following order: selecting the file to analyze from the file tree on the left, verifying the violation locations through line numbers and highlights in the central code/document viewer, and viewing the rule, severity, confirmed/candidate status, and patch notes at a glance in the violation list on the right. At this point, clicking on a violation in the list immediately jumps to its location, enhancing user convenience. A violation-count badge next to each file name allows the user to prioritize which file to view first.

그림 2와 그림 3은 분석 완료 후 코드와 위반 사항을 비교하는 메인 검증 화면을 나타낸다. 검토 화면은 3분할 레이아웃을 사용한다. 사용자는 좌측 파일 트리에서 분석 파일을 선택하고, 중앙 코드·문서 뷰어에서 행 번호와 강조 표시로 위반 위치를 확인하며, 우측 위반 목록에서 규칙, 심각도, 확정·후보 상태 및 패치 노트를 확인한다. 목록의 위반 사항을 클릭하면 해당 위치로 즉시 이동하며, 파일명 옆 위반 건수 배지는 검토 우선순위 결정을 지원한다.

**Figure 2. Main screen and panel structure. / 그림 2. 메인 화면 및 패널 구조.**

### Final Report Screen / 최종 보고서 화면

The report (see Fig. 3) screen summarizes confirmed violations, violation candidates, and totals as cards at the top, and divides the inspection axes---such as common security, algorithms, modes, documents, and traceability---into per-category tables, introducing an information hierarchy that lets the user first identify where failures or review needs arose before drilling down into details. Alongside output buttons such as PDF and print, the right panel additionally shows the per-source (code/document) counts as auxiliary information, and finally the AI summarizes the content so that the results can be checked at a glance.

보고서 화면은 상단 카드에 확정 위반, 위반 후보 및 총계를 요약하고, 공통 보안, 알고리즘, 운용 모드, 문서 및 추적성 등의 검사 축을 범주별 표로 구분한다. 사용자는 세부 내용을 확인하기 전에 실패 또는 검토 필요 영역을 먼저 파악한다. PDF 및 인쇄 출력 버튼과 함께 우측 패널은 출처별 코드·문서 건수를 보조 정보로 제시하며, AI가 내용을 최종 요약하여 결과를 한눈에 확인하도록 한다.

Ultimately, an IDE-style three-pane layout was adopted to provide an integrated working environment in which the analysis target and the analysis results can be examined simultaneously. The actual implementation video can be viewed at https://www.youtube.com/watch?v=6zdJuxVIIgmE.

궁극적으로 분석 대상과 분석 결과를 동시에 검토하는 통합 작업 환경을 제공하기 위해 IDE 형태의 3분할 레이아웃을 채택한다. 실제 구현 영상은 제시된 링크에서 확인한다.

**Figure 3. Main screen and Patch Notes. / 그림 3. 메인 화면 및 패치 노트.**

Table 1 shows the main technology stack used to implement the system.

표 1은 시스템 구현에 사용한 주요 기술 스택을 나타낸다.

**Table 1. System implementation technology stack. / 표 1. 시스템 구현 기술 스택.**

| Component | Technology used |
|---|---|
| Backend | FastAPI (Python 3.11+) |
| Frontend | React 18 + Zustand |
| C/C++ parser | libclang + pycparser |
| PDF extraction | PyMuPDF + pdfplumber + MarkItDown |
| LLM | Gemini 2.5 Flash Lite; Gemini 2.0 Flash Vision OCR |
| Vector store | ChromaDB |
| Rule format | YAML |

# 5. Evaluation / 평가

The evaluation of this study was carried out on the web prototype implemented in Section 4.

본 연구의 평가는 제4절에서 구현한 웹 프로토타입을 대상으로 수행한다.

~~In this study, the evaluation is conducted on a verified violation dataset from which FPs have been removed through analysis of actual KISA LEA code. The quantitative detection-performance evaluation in Section 5.1 was derived not from modules that have actually obtained KCMVP certification, but from synthetic data with violations intentionally inserted.~~

<span style="color:red">The initial evaluation uses an author-labeled dataset derived through analysis of KISA LEA code. The quantitative evaluation in Section 5.1 uses synthetic data with intentionally inserted violations rather than certified production modules.</span>

초기 평가는 KISA LEA 코드 분석을 바탕으로 저자가 라벨링한 데이터셋을 사용한다. 제5.1절의 정량 평가는 인증된 운영 모듈이 아니라 의도적으로 위반을 삽입한 합성 데이터를 사용한다.

## 5.1. Experimental Evaluation / 실험 평가

### Test Dataset / 시험 데이터셋

~~Based on a C-language implementation of the LEA algorithm and the security policy document of a validated cryptographic module, we constructed an archive in which rule-set violations were intentionally injected. The evaluation dataset consists of seven sets of code-ZIP and design-specification-PDF pairs, covering major validation areas such as the CBC and CTR modes of operation, key management, zeroization, random-number generation, and the LEA key schedule, round function, and Monte Carlo Test (MCT) loop. The Ground Truth (GT) is based on 128 verified cases obtained by removing FPs through analysis of actual KISA LEA code.~~

<span style="color:red">Based on a C-language implementation of LEA and a validated module's security policy, the authors constructed seven code-ZIP and design-PDF pairs with intentionally injected violations. They cover CBC/CTR modes, key management, zeroization, random-number generation, the LEA key schedule, round function, and MCT loop. The 128 cases are author-reviewed labels; independent annotation has not yet been completed.</span>

LEA의 C 언어 구현과 검증된 모듈의 보안 정책을 바탕으로 저자들은 의도적으로 위반을 삽입한 코드 ZIP 및 설계 PDF 쌍 7개를 구축한다. 데이터셋은 CBC·CTR 모드, 키 관리, 영구 삭제, 난수 생성, LEA 키 스케줄, 라운드 함수 및 MCT 루프를 포함한다. 128개 사례는 저자가 검토한 라벨이며 독립 주석은 아직 완료되지 않았다.

### Code Violation Detection Performance / 코드 위반 탐지 성능

<span style="color:red">This initial evaluation characterizes detection on the author-constructed dataset and the L3 filtering behavior recorded in a legacy run. Recall measures missed labeled violations, while the filtering indicator records removed author-labeled FP candidates and removed labeled TPs. It does not directly measure human review time. Table 2 reports the legacy values; the original run lacks an immutable manifest tying it to the current repository snapshot.</span>

초기 평가는 저자 구축 데이터셋의 탐지 특성과 기존 실행에서 기록한 L3 필터링 동작을 분석한다. 재현율은 누락된 라벨 위반을 측정하고, 필터링 지표는 제거된 저자 라벨 오탐 후보와 제거된 참양성을 기록한다. 이 지표는 인간 검토 시간을 직접 측정하지 않는다. 표 2는 기존 값을 보고하며, 원 실행과 현재 저장소 스냅샷을 연결하는 불변 매니페스트는 존재하지 않는다.

**Table 2. Code violation detection performance (Sets 1--7, based on 128 GT cases). / 표 2. 코드 위반 탐지 성능.**

| Metric | Result |
|---|---|
| True Positive (TP) | 128 cases |
| False Negative (FN) | 0 cases |
| Recall | 100% |
| L1-stage False Positive candidates | 46 cases |
| L3 filtering: FP removal | 9/46 (19.6%) |
| <span style="color:red">Author-labeled TPs removed by L3</span> | 0 cases |
| Final False Positive (FP) | 37 cases |
| Precision | 77.6% |
| F1-score | 87.4% |

<span style="color:red">On this dataset, the legacy run recorded all 128 labeled code cases and L3 removed 9 of 46 author-labeled FP candidates without removing an author-labeled TP. These observations motivate the layered design but do not isolate L2 or establish reduced human review effort. Document-rule outputs were inspected qualitatively; no independently labeled document confusion matrix is claimed. Because `missing`-type rules judge absence as a violation, delegation to other files can still yield false candidates.</span>

이 데이터셋에서 기존 실행은 라벨된 코드 사례 128건을 모두 기록하였으며, L3는 저자 라벨 오탐 후보 46건 중 9건을 제거하고 저자 라벨 참양성은 제거하지 않았다. 이 관찰은 계층 구조의 동기를 제공하지만 L2를 분리하거나 인간 검토 노력의 감소를 입증하지 않는다. 문서 규칙 출력은 정성적으로 검토하며 독립 라벨이 부여된 문서 혼동행렬을 주장하지 않는다. `missing` 유형 규칙은 부재를 위반으로 판단하므로 다른 파일에 기능을 위임한 경우에도 오탐 후보가 발생할 수 있다.

### Case Study on a Real Cryptographic Module / 실제 암호 모듈 사례 연구

<span style="color:red">In addition to the synthetic dataset, we inspected a commercial cryptographic module developed for KCMVP submission. A reproducibility audit found that the earlier draft mixed two counting scopes: the archive contains 34 C files with 11,983 physical lines, whereas including 25 header files produces 59 C/H files with 14,511 physical lines. The earlier value of 0.58 cases/KLOC therefore combined a C-only numerator/denominator with a C/H description. Moreover, saved legacy runs contained different candidate counts and lacked immutable code/input/prompt manifests. We consequently withdraw the candidate-frequency value from the performance claims and retain this dataset only as a qualitative case study until a manifest-bound rerun and independent labeling are completed. Certification status alone is not used to label every static-analysis candidate as an FP.</span>

합성 데이터셋과 함께 KCMVP 제출을 위해 개발한 상용 암호 모듈을 검사한다. 재현성 감사 결과, 이전 초안은 C 파일 34개의 11,983 물리적 LOC와 헤더 25개를 포함한 C/H 파일 59개의 14,511 물리적 LOC라는 두 집계 범위를 혼합한다. 따라서 기존의 0.58건/KLOC는 C 전용 분자·분모와 C/H 설명을 결합한 값이다. 저장된 기존 실행의 후보 수 또한 서로 다르고 불변 코드·입력·프롬프트 매니페스트가 없다. 이에 후보 빈도를 성능 주장으로부터 철회하며, 매니페스트 기반 재실행과 독립 라벨링을 완료할 때까지 해당 데이터셋을 정성적 사례 연구로만 유지한다. 인증 상태만으로 모든 정적 분석 후보를 오탐으로 라벨링하지 않는다.

**Table 3. Re-audited scope of the commercial-module case study. / 표 3. 상용 모듈 사례 연구의 재감사 범위.**

| Metric | Result |
|---|---|
| C source scope | 34 files / 11,983 physical LOC |
| C and header scope | 59 files / 14,511 physical LOC |
| Candidate count | Withheld pending canonical rerun |
| Candidate frequency | Not reported |
| Ground-truth status | Independent labeling pending |

<span style="color:red">Accordingly, this case study cannot presently establish a real-world FP rate or generalization performance. It remains useful for identifying parser, naming, and cross-file limitations, but not for estimating predictive accuracy.</span>

따라서 이 사례 연구는 현재 실제 환경의 오탐률이나 일반화 성능을 확립하지 못한다. 파서, 명명 및 파일 간 분석의 한계를 식별하는 데에는 유용하지만 예측 정확도를 추정하는 근거로 사용하지 않는다.

<span style="color:red">Illustrative candidate classes observed in legacy runs, but not independently labeled, include residual-data clearing items (COM-001). Even when source code contains zeroization, a compiler may eliminate it as a dead store. Future intermediate-representation or symbolic-execution analysis should account for compiler optimization.</span>

기존 실행에서 관찰하였으나 독립 라벨링하지 않은 예시 후보 유형은 잔류 데이터 삭제 항목(COM-001)을 포함한다. 소스 코드에 영구 삭제 구문이 있더라도 컴파일러는 이를 불필요한 저장으로 제거할 수 있다. 향후 중간 표현 또는 기호 실행 분석은 컴파일러 최적화를 고려해야 한다.

Items corresponding to the absence of test infrastructure do not surface in functional behavior tests and are currently detected only through rule-based checks. This system implements a basic level of traceability verification, but, because of its reliance on regular-expression-based function extraction, omissions appear to have occurred for non-standard naming conventions and macro-wrapped functions. It is expected that detection accuracy for this type of issue can be improved by combining it with file-tree-structure analysis and reinforcing it with a complete AST-based implementation.

시험 기반 구조의 부재에 해당하는 항목은 기능 동작 시험에서 드러나지 않으며 현재 규칙 기반 검사만으로 탐지한다. 시스템은 기본 수준의 추적성 검증을 구현하지만 정규표현식 기반 함수 추출에 의존하므로 비표준 명명 규칙과 매크로로 감싼 함수에서 누락이 발생할 수 있다. 파일 트리 구조 분석을 결합하고 완전한 AST 기반 구현으로 강화하여 탐지 정확도를 개선할 수 있다.

## 5.2. Limitations Analysis / 한계 분석

1. **TRC traceability verification's reliance on regular expressions.** Because matching depends mainly on regular expressions and naming rules for whether header function declarations or in-document references exist, there is a risk of omissions and misidentifications for non-standard naming conventions, macro-wrapped APIs, and the like.

   **TRC 추적성 검증의 정규표현식 의존성.** 헤더 함수 선언 또는 문서 내 참조의 존재 여부가 주로 정규표현식과 명명 규칙에 의존하므로, 비표준 명명 규칙과 매크로로 감싼 API 등에서 누락 및 오식별 위험이 존재한다.

2. **The gap between the evaluation dataset and real-world environments.** Since this evaluation, centered on publicly available and synthetic materials, does not fully represent the scale or coding practices of commercial codebases that actually apply for KCMVP certification, a follow-up evaluation that utilizes actual confidential data through cooperation with certification authorities is required.

   **평가 데이터셋과 실제 환경 간 차이.** 공개 및 합성 자료 중심의 평가는 실제 KCMVP 인증을 신청하는 상용 코드베이스의 규모와 코딩 관행을 충분히 대표하지 못하므로, 인증 기관과의 협력을 통해 실제 기밀 데이터를 일부 활용하는 후속 평가가 요구된다.

3. <span style="color:red">**Author-constructed Ground Truth and algorithm scope.** The 128 labeled cases were constructed and reviewed by the authors and are centered on LEA. Independent blinded annotation and algorithm-specific test sets for AES, SEED, and other KCMVP algorithms are required before the reported recall and precision can be generalized.</span>

   **저자 구축 정답 데이터와 알고리즘 범위.** 라벨 사례 128건은 저자가 구축하고 검토하였으며 LEA를 중심으로 한다. 보고한 재현율과 정밀도를 일반화하기 전에 독립 블라인드 주석과 AES, SEED 및 기타 KCMVP 알고리즘별 시험 세트가 요구된다.

4. <span style="color:red">**Unisolated contribution of L2.** The reported end-to-end results do not independently quantify the effect of RAG evidence. A controlled paired comparison between L1+L3 without retrieved evidence and L1+L2+L3, holding candidates, prompts, model parameters, and repetitions constant, is required. Until then, L2 is supported as an evidence-provision mechanism rather than as a demonstrated accuracy improvement.</span>

   **분리되지 않은 L2 기여도.** 보고한 종단 간 결과는 RAG 근거의 효과를 독립적으로 정량화하지 않는다. 후보, 프롬프트, 모델 매개변수 및 반복 횟수를 고정한 상태에서 검색 근거를 제외한 L1+L3와 L1+L2+L3를 통제된 쌍으로 비교해야 한다. 그 전까지 L2는 입증된 정확도 향상이 아니라 근거 제공 메커니즘으로 간주한다.

5. <span style="color:red">**Threshold calibration and operational cost.** The 65--74 re-evaluation interval was selected heuristically. A calibration and threshold-sensitivity analysis is required together with manifest-bound measurements of elapsed time, API calls, tokens, and pricing snapshots. Legacy telemetry is not promoted to a final cost claim because it cannot be tied to an immutable experiment version.</span>

   **임계값 보정 및 운영 비용.** 65~74 재평가 구간은 휴리스틱으로 선택하였다. 경과 시간, API 호출, 토큰 및 가격 스냅샷을 매니페스트에 결합하여 측정하고 보정 및 임계값 민감도 분석을 수행해야 한다. 기존 텔레메트리는 불변 실험 버전과 연결할 수 없으므로 최종 비용 주장으로 제시하지 않는다.

6. **Evidence extraction limitations due to document expression diversity.** Security policy documents and design specifications may describe identical requirements using different terminology and structures depending on the authoring organization, format, and version. In particular, for documents centered on tables, appendices, scanned images, and abbreviations, context may become fragmented or inter-item relationships may be lost during the PDF text extraction process. In such cases, the system may fail to retrieve relevant evidence sufficiently, or may link sentences that are semantically adjacent but are not direct evidence. Accordingly, future work requires reinforcement of document structure recognition, table-level parsing, and per-requirement evidence normalization techniques.

   **문서 표현 다양성에 따른 근거 추출 한계.** 보안 정책 문서와 설계 명세서는 작성 기관, 형식 및 버전에 따라 동일한 요구사항을 서로 다른 용어와 구조로 기술할 수 있다. 표, 부록, 스캔 이미지 및 약어 중심의 문서에서는 PDF 텍스트 추출 과정에서 문맥이 단편화되거나 항목 간 관계가 손실될 수 있다. 이 경우 관련 근거를 충분히 검색하지 못하거나 의미상 인접하지만 직접 근거가 아닌 문장을 연결할 수 있다. 따라서 문서 구조 인식, 표 단위 파싱 및 요구사항별 근거 정규화 기법의 강화가 요구된다.

# 6. Conclusion / 결론

In this study, we proposed and implemented a hybrid framework for KCMVP pre-compliance inspection that ties rule-based static analysis (L1), RAG-based guideline-evidence attachment (L2), and LLM-based semantic re-evaluation (L3) into a single funnel-shaped pipeline. The system applies rules---covering common security, LEA implementation constraints, multiple modes of operation, submission-document formats, and code--document traceability---that are formalized in YAML, and through the KCMVP guideline mapping linked to the rule identifiers, it allows evidence to be attached to the interpretation of the results.

본 연구에서는 규칙 기반 정적 분석(L1), RAG 기반 지침 근거 첨부(L2) 및 LLM 기반 의미론적 재평가(L3)를 하나의 퍼널형 파이프라인으로 결합한 KCMVP 사전 적합성 검사 하이브리드 프레임워크를 제안하고 구현한다. 시스템은 공통 보안, LEA 구현 제약, 복수 운용 모드, 제출 문서 형식 및 코드-문서 추적성을 포괄하는 YAML 규칙을 적용하며, 규칙 식별자와 연결된 KCMVP 지침 매핑을 통해 결과 해석에 근거를 첨부한다.

~~Through the prototype evaluation, we confirmed the effectiveness of the complementary structure in which the deterministic L1 secures a broad detection coverage and L3 reduces false positives through contextual reasoning. The multi-layered evidence retrieval at the L2 stage attaches standards and guideline citations to the violation items, aiding interpretability and the prioritization of remediation.~~

<span style="color:red">Through the initial LEA-centered prototype evaluation, we observed the complementary behavior in which deterministic L1 provides broad candidate coverage and L3 can remove some labeled false positives through contextual reasoning. The multi-layered evidence retrieval at L2 attaches standards and guideline citations to violation items, but its independent effect on decision accuracy has not yet been established.</span> In addition, the system incorporates practical mechanisms tailored to the non-standard nature of real code, such as preprocessing/parsing fallbacks, domain-oriented false-positive mitigation, and multi-stage detection of common-security rules.

초기 LEA 중심 프로토타입 평가에서는 결정론적 L1이 폭넓은 후보 범위를 제공하고 L3가 문맥적 추론을 통해 일부 라벨 오탐을 제거할 수 있는 상호 보완적 동작을 관찰한다. L2의 다층 근거 검색은 위반 항목에 표준 및 지침 인용을 첨부하지만, 판단 정확도에 대한 독립적 효과는 아직 확립되지 않았다. 또한 시스템은 전처리·파싱 대체 경로, 도메인 중심 오탐 완화 및 공통 보안 규칙의 다단계 탐지 등 비표준적인 실제 코드에 대응하는 실무적 메커니즘을 포함한다.

On the other hand, this system still remains a pre-certification auxiliary tool. Some of the AST rules rely on a regex fallback, the traceability verification has limitations centered on declaration and text matching, and the experiments were conducted primarily on publicly available and synthetic materials, so they cannot be regarded as representative of the entire set of actually submitted modules. Future work is as follows.

반면 본 시스템은 여전히 사전 인증 보조 도구이다. 일부 AST 규칙은 정규표현식 대체 경로에 의존하고, 추적성 검증은 선언 및 텍스트 매칭 중심의 한계를 가지며, 실험은 주로 공개 및 합성 자료를 대상으로 수행한다. 따라서 실제 제출 모듈 전체를 대표한다고 간주할 수 없다. 향후 연구는 다음과 같다.

- **Advancement of AST Analysis:** Migrate the rules that currently rely on fallbacks to structural analysis by utilizing pycparser, tree-sitter, and similar tools.
  - **AST 분석 고도화:** pycparser, tree-sitter 등의 도구를 활용하여 현재 대체 경로에 의존하는 규칙을 구조 분석으로 전환한다.
- **Strengthening of Traceability Verification:** Extend the extraction and matching logic to encompass macros, multi-line declarations, and API mappings listed in design-specification tables.
  - **추적성 검증 강화:** 매크로, 다중 행 선언 및 설계 명세서 표의 API 매핑을 포함하도록 추출 및 매칭 로직을 확장한다.
- **Validation on Real Data:** Conduct reproducibility evaluations using actual submission deliverables in part, through cooperation with certification authorities and industry.
  - **실제 데이터 검증:** 인증 기관 및 산업계와 협력하여 실제 제출 산출물의 일부를 활용한 재현성 평가를 수행한다.
- **Expansion of Algorithm and Mode Coverage:** The current LEA-centered support is to be extended in two directions. (1) Within block ciphers: expand the rule set to other KCMVP-approved block ciphers such as AES, SEED, and ARIA. (2) Across cryptographic primitive types: investigate extension to hash functions (SHA-256, SHA-3, LSH, etc.) and public-key algorithms (EC-KCDSA, RSA, etc.). Hash functions require inspection items distinct from block ciphers, such as input-length restrictions, padding handling, and fixed initialization-vector verification. Public-key algorithms demand stateful, composite checks including key-length adequacy, PRNG coupling, signature-nature-verification ordering, and certificate-chain handling. In particular, because public-key operations (key generation, signing, and verification) are distributed across separate functions and files, the current single-file-centric AST analysis must be strengthened into cross-file call-flow analysis.
  - **알고리즘 및 운용 모드 범위 확장:** 현재 LEA 중심 지원을 두 방향으로 확장한다. 첫째, 블록 암호 내에서는 AES, SEED 및 ARIA와 같은 다른 KCMVP 승인 블록 암호로 규칙 세트를 확장한다. 둘째, 암호 프리미티브 유형 간에는 해시 함수와 공개키 알고리즘으로의 확장을 검토한다. 해시 함수는 입력 길이 제한, 패딩 처리 및 고정 초기화 벡터 검증과 같은 별도의 검사 항목이 필요하다. 공개키 알고리즘은 키 길이 적절성, PRNG 결합, 서명·검증 순서 및 인증서 체인 처리 등의 상태 기반 복합 검사가 필요하다. 공개키 연산은 별도 함수와 파일에 분산되므로 현재의 단일 파일 중심 AST 분석을 파일 간 호출 흐름 분석으로 강화해야 한다.
- **L3 Operational Optimization:** Study the cost--quality balance, including transitions to local and open-source LLMs, call limits, batching strategies, and regression testing.
  - **L3 운영 최적화:** 로컬·오픈소스 LLM 전환, 호출 제한, 배치 전략 및 회귀 시험을 포함한 비용-품질 균형을 연구한다.

Building on these directions, we expect that this work can lead to subsequent standardization and tool development aimed at reducing the review costs entailed by certification preparation.

이러한 방향을 바탕으로 본 연구는 인증 준비에 수반되는 검토 비용을 줄이기 위한 후속 표준화 및 도구 개발로 이어질 것으로 기대한다.

# Back Matter / 후면부

## Author Contributions / 저자 기여

~~Conceptualization, methodology, software, validation, formal analysis, investigation, data curation, writing---original draft preparation, writing---review and editing, visualization, supervision, and project administration: contributions to be confirmed by all authors before submission. All authors have read and agreed to the published version of the manuscript.~~

<span style="color:red">Conceptualization, methodology, software, validation, formal analysis, investigation, data curation, writing---original draft preparation, writing---review and editing, visualization, supervision, and project administration: all authors. All authors have read and agreed to the published version of the manuscript.</span>

개념화, 방법론, 소프트웨어, 검증, 형식 분석, 조사, 데이터 큐레이션, 초안 작성, 검토 및 편집, 시각화, 감독 및 프로젝트 관리는 모든 저자가 수행한다. 모든 저자는 원고의 출판본을 읽고 이에 동의한다. **단, 제출 전에 모든 저자가 실제 CRediT 역할을 확인해야 한다.**

## Funding / 연구비

This research received no external funding.

본 연구는 외부 연구비를 지원받지 않는다.

## Institutional Review Board Statement / 기관생명윤리위원회 승인

Not applicable.

해당하지 않는다.

## Informed Consent Statement / 사전 동의

Not applicable.

해당하지 않는다.

## Data Availability Statement / 데이터 가용성

~~The data presented in this study are available from the corresponding author upon reasonable request.~~

<span style="color:red">The repository exposes the implementation and non-sensitive rule assets. The legacy evaluation lacks an immutable public manifest; a sanitized corpus, sidecar labels, experiment configuration, and hashed result bundle are planned as supplementary artifacts after license and disclosure review. Restricted commercial-module inputs cannot be redistributed and may be available only subject to permission.</span>

저장소는 구현과 비민감 규칙 자산을 공개한다. 기존 평가에는 불변 공개 매니페스트가 없으며, 라이선스 및 공개 검토 후 정제 코퍼스, 사이드카 라벨, 실험 설정 및 해시 결과 번들을 보충 자료로 제공할 예정이다. 제한된 상용 모듈 입력은 재배포할 수 없으며 허가를 전제로만 제공할 수 있다.

## Conflicts of Interest / 이해상충

The authors declare no conflicts of interest.

저자들은 이해상충이 없음을 선언한다.

## Abbreviations / 약어

| Abbreviation | Full term | 한국어 |
|---|---|---|
| AI | Artificial Intelligence | 인공지능 |
| API | Application Programming Interface | 응용 프로그램 인터페이스 |
| AST | Abstract Syntax Tree | 추상 구문 트리 |
| FN | False Negative | 미탐(FN) |
| FP | False Positive | 오탐(FP) |
| KCMVP | Korean Cryptographic Module Validation Program | 암호모듈 검증제도 |
| KISA | Korea Internet & Security Agency | 한국인터넷진흥원 |
| LEA | Lightweight Encryption Algorithm | 경량 암호 알고리즘 |
| LLM | Large Language Model | 대규모 언어 모델 |
| RAG | Retrieval-Augmented Generation | 검색 증강 생성 |
| TP | True Positive | 참양성(TP) |


---

## References

아래 블록은 `references_generated.tex`의 전체 내용을 문자 단위로 보존한다. 참고문헌 28개와 각 `\\bibitem` 인용 키를 모두 포함한다.

```latex
\begin{thebibliography}{999}

\bibitem[{National Intelligence Service (NIS)}(2025)]{nis2025}
{National Intelligence Service (NIS)}.
\newblock Guidelines for Cryptographic Module Testing and Validation.
\newblock Technical report, National Intelligence Service,  2025.
\newblock NIS Guideline (enacted 2021-11-01, revised 2025-06-01). In Korean.

\bibitem[{Presidential Decree of the Republic of Korea}(2024)]{cybersec2024}
{Presidential Decree of the Republic of Korea}.
\newblock Cyber Security Work Regulations,  2024.
\newblock Presidential Decree No.~34287 (partial amendment 2024-03-05,
  effective 2025-01-01). In Korean.

\bibitem[{Presidential Decree of the Republic of Korea}(2025)]{egov2025}
{Presidential Decree of the Republic of Korea}.
\newblock Article 69 of the Enforcement Decree of the Electronic Government
  Act,  2025.
\newblock Presidential Decree No.~35948 (amendment by other law 2025-12-30,
  effective 2026-01-02). In Korean.

\bibitem[{National Institute of Standards and Technology
  (NIST)}(2001)]{fips1402}
{National Institute of Standards and Technology (NIST)}.
\newblock Security Requirements for Cryptographic Modules.
\newblock Technical Report FIPS 140-2, NIST,  2001.
\newblock May 2001, updated December 3, 2002.

\bibitem[{National Institute of Standards and Technology
  (NIST)}(2019)]{fips1403}
{National Institute of Standards and Technology (NIST)}.
\newblock Security Requirements for Cryptographic Modules.
\newblock Technical Report FIPS 140-3, NIST,  2019.
\newblock March 2019.

\bibitem[{Korean Agency for Technology and
  Standards}(2015{\natexlab{a}})]{ks19790}
{Korean Agency for Technology and Standards}.
\newblock {KS X ISO/IEC 19790:2015} -- Information Technology -- Security
  Techniques -- Security Requirements for Cryptographic Modules,  2015.
\newblock Korean adoption of ISO/IEC 19790:2012.

\bibitem[{Korean Agency for Technology and
  Standards}(2015{\natexlab{b}})]{ks24759}
{Korean Agency for Technology and Standards}.
\newblock {KS X ISO/IEC 24759:2015} -- Information Technology -- Security
  Techniques -- Test Requirements for Cryptographic Modules,  2015.
\newblock Korean adoption of ISO/IEC 24759:2014.

\bibitem[Hong et~al.(2014)Hong, Lee, Kim, Kwon, Ryu, and Lee]{lea2014}
Hong, D.; Lee, J.K.; Kim, D.C.; Kwon, D.; Ryu, K.H.; Lee, D.G.
\newblock {LEA}: A 128-Bit Block Cipher for Fast Encryption on Common
  Processors.
\newblock In Proceedings of the WISA 2013. Springer,  2014, Vol. 8267, {\em
  Lecture Notes in Computer Science}.

\bibitem[{National Institute of Standards and Technology
  (NIST)}(2023)]{aes2023}
{National Institute of Standards and Technology (NIST)}.
\newblock Advanced Encryption Standard ({AES}).
\newblock Technical Report FIPS 197-upd1, NIST,  2023.
\newblock Updated May 9, 2023.

\bibitem[{Korea Telecommunications Technology Association
  (TTA)}(2005)]{seed2005}
{Korea Telecommunications Technology Association (TTA)}.
\newblock 128-Bit Symmetric Block Cipher ({SEED}).
\newblock Technical Report TTAS.KO-12.0004/R1, TTA,  2005.
\newblock December 2005. In Korean.

\bibitem[Zhao et~al.(2023)Zhao, Zhou, Li, Tang, Wang, Hou, Min, Zhang, Zhang,
  Dong, Du, Yang, Chen, Chen, Jiang, Ren, Li, Tang, Liu, Liu, Nie, and
  Wen]{llmsurvey2023}
Zhao, W.X.; Zhou, K.; Li, J.; Tang, T.; Wang, X.; Hou, Y.; Min, Y.; Zhang, B.;
  Zhang, J.; Dong, Z.;  et~al.
\newblock A Survey of Large Language Models.
\newblock {\em arXiv preprint arXiv:2303.18223} {\bf 2023}.

\bibitem[{Google}(2025)]{gemini25}
{Google}.
\newblock We're Expanding Our {Gemini} 2.5 Family of Models.
\newblock Google Blog,  2025.

\bibitem[Lewis et~al.(2020)Lewis, Perez, Piktus, Petroni, Karpukhin, Goyal,
  K{\"u}ttler, Lewis, tau Yih, Rockt{\"a}schel, Riedel, and Kiela]{rag2020}
Lewis, P.; Perez, E.; Piktus, A.; Petroni, F.; Karpukhin, V.; Goyal, N.;
  K{\"u}ttler, H.; Lewis, M.; tau Yih, W.; Rockt{\"a}schel, T.;  et~al.
\newblock Retrieval-Augmented Generation for Knowledge-Intensive {NLP} Tasks.
\newblock In Proceedings of the Advances in Neural Information Processing
  Systems 33 (NeurIPS),  2020.

\bibitem[Rahaman et~al.(2019)Rahaman, Xiao, Afrose, Shaon, Tian, Frantz,
  Kantarcioglu, and Yao]{cryptoguard2019}
Rahaman, S.; Xiao, Y.; Afrose, S.; Shaon, F.; Tian, K.; Frantz, M.;
  Kantarcioglu, M.; Yao, D.
\newblock {CryptoGuard}: High Precision Detection of Cryptographic
  Vulnerabilities in Massive-Sized {Java} Projects.
\newblock In Proceedings of the Proceedings of the 2019 ACM SIGSAC Conference
  on Computer and Communications Security (CCS). ACM,  2019.

\bibitem[Kr{\"u}ger et~al.(2017)Kr{\"u}ger, Nadi, Reif, Ali, Mezini, Bodden,
  G{\"o}pfert, G{\"u}nther, Weinert, Demmler, and Kamath]{cognicrypt2017}
Kr{\"u}ger, S.; Nadi, S.; Reif, M.; Ali, K.; Mezini, M.; Bodden, E.;
  G{\"o}pfert, F.; G{\"u}nther, F.; Weinert, C.; Demmler, D.;  et~al.
\newblock {CogniCrypt}: Supporting Developers in Using Cryptography.
\newblock In Proceedings of the Proceedings of the 32nd IEEE/ACM International
  Conference on Automated Software Engineering (ASE). IEEE,  2017.

\bibitem[{National Institute of Standards and Technology (NIST)}()]{cavp}
{National Institute of Standards and Technology (NIST)}.
\newblock Cryptographic Algorithm Validation Program ({CAVP}).
\newblock [Online]. Available:
  \url{https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program}.
\newblock Accessed: 2026-03-31.

\bibitem[{National Security Research Institute (NSR)}(2023)]{nsrguide2023}
{National Security Research Institute (NSR)}.
\newblock {\em Cryptographic Module Pre-validation Service User Guide}.
\newblock KCMVP,  2023.
\newblock Manual v1.0. [Online]. Available: \url{https://www.kcmvp.or.kr}. In
  Korean.

\bibitem[Aho et~al.(2006)Aho, Lam, Sethi, and Ullman]{aho2006}
Aho, A.V.; Lam, M.S.; Sethi, R.; Ullman, J.D.
\newblock {\em Compilers: Principles, Techniques, and Tools}, 2nd ed.; Pearson
  Education,  2006.

\bibitem[Singer-Vine(2016)]{pdfplumber}
Singer-Vine, J.
\newblock pdfplumber.
\newblock GitHub repository,  2016.
\newblock [Online]. Available: \url{https://github.com/jsvine/pdfplumber}.
  Accessed: 2026-03-29.

\bibitem[{Artifex Software}(2024)]{pymupdf}
{Artifex Software}.
\newblock {PyMuPDF}: {Python} Bindings for {MuPDF}.
\newblock [Online]. Available: \url{https://pymupdf.readthedocs.io/},  2024.
\newblock Accessed: 2026-03-29.

\bibitem[{Google DeepMind}(2025)]{gemini20flash}
{Google DeepMind}.
\newblock {Gemini} 2.0 Flash.
\newblock Google DeepMind Blog,  2025.
\newblock [Online]. Available:
  \url{https://deepmind.google/technologies/gemini/flash/}. Accessed:
  2026-03-31.

\bibitem[{Korea Internet \& Security Agency (KISA)}(2025)]{kisaguide2025}
{Korea Internet \& Security Agency (KISA)}.
\newblock Cryptographic Module Submission Authoring Guide.
\newblock Technical report, KISA,  2025.

\bibitem[{National Security Research Institute (NSR)}()]{leaspec}
{National Security Research Institute (NSR)}.
\newblock 128-Bit Block Cipher {LEA} Specification.
\newblock Technical report, NSR.

\bibitem[{National Intelligence Service (NIS) and National Security Research
  Institute (NSR)}(2024)]{nisimpl2024}
{National Intelligence Service (NIS) and National Security Research Institute
  (NSR)}.
\newblock Guide for Vendor Implementations Part 2: Implementation Guide for
  Validation-Target Cryptographic Algorithms.
\newblock Technical report, NIS/NSR,  2024.

\bibitem[{LLVM Project}(2010)]{libclang}
{LLVM Project}.
\newblock Clang: A {C} Language Family Frontend for {LLVM}.
\newblock [Online]. Available: \url{https://clang.llvm.org/},  2010.
\newblock Accessed: 2026-03-31.

\bibitem[Bendersky(2008)]{pycparser}
Bendersky, E.
\newblock pycparser: Complete {C99} Parser in Pure {Python}.
\newblock GitHub repository,  2008.
\newblock [Online]. Available: \url{https://github.com/eliben/pycparser}.
  Accessed: 2026-03-29.

\bibitem[{Microsoft}(2024)]{markitdown}
{Microsoft}.
\newblock {MarkItDown}: {Python} Tool for Converting Files and Office Documents
  to {Markdown}.
\newblock GitHub repository,  2024.
\newblock [Online]. Available: \url{https://github.com/microsoft/markitdown}.
  Accessed: 2026-03-29.

\bibitem[{National Cyber Security Center (NCSC)}()]{ncsc2026}
{National Cyber Security Center (NCSC)}.
\newblock List of Validated Cryptographic Modules.
\newblock [Online database], KCMVP. [Online]. Available:
  \url{https://www.ncsc.go.kr/}.
\newblock Accessed: 2026-05-21.

\end{thebibliography}
```


---

# 부록 A. 최신 LaTeX 원문 완전 보존층

> Markdown 변환 중 인용·각주·상호참조가 소실되지 않았음을 검증하기 위한 원문층이다. 요청에 따라 그림 파일 삽입 명령(`includegraphics`)만 제외하고 캡션은 그대로 보존한다.

## main.tex

```latex
% MDPI submission version of the complete LNCS manuscript.
% Compile with pdfLaTeX on Overleaf.
\documentclass[applsci,article,submit,pdftex,moreauthors]{Definitions/mdpi}

\firstpage{1}
\makeatletter
\setcounter{page}{\@firstpage}
\makeatother
\pubvolume{1}
\issuenum{1}
\articlenumber{0}
\pubyear{2026}
\copyrightyear{2026}
\datereceived{ }
\daterevised{ }
\dateaccepted{ }
\datepublished{ }

\input{packages}

\Title{AI-Based KCMVP Pre-Certification System: A Hybrid Model of Rule-Based Detection and LLM Semantic Analysis}

\Author{Su-Been Cho $^{1}$, Do-Yun Park $^{1}$, Da-Eun Lim $^{1}$, Jae-Hwan Kim $^{1}$, Su-Min Jeong $^{1}$, Yu-Lim Hyoung $^{1}$ and Hwa-Jeong Seo $^{1,}$*}

\AuthorNames{Su-Been Cho, Do-Yun Park, Da-Eun Lim, Jae-Hwan Kim, Su-Min Jeong, Yu-Lim Hyoung and Hwa-Jeong Seo}

\address{$^{1}$ \quad Department of Convergence Security, Hansung University, Seoul 02876, South Korea; chosubin1208@gmail.com (S.-B.C.); rhcp030418@gmail.com (D.-Y.P.); limadaeun@gmail.com (D.-E.L.); jaedol2023@gmail.com (J.-H.K.); jeong9sumin@gmail.com (S.-M.J.); yulim4hyoung@gmail.com (Y.-L.H.); hwajeong84@gmail.com (H.-J.S.)}

\corres{Correspondence: hwajeong84@gmail.com (H.-J.S.)}

\input{00abstract}

\begin{document}

\input{01introduction}
\input{02background}
\input{03system_design}
\input{04prototype}
\input{05evaluation}
\input{06conclusion}

\vspace{6pt}

% Please verify the CRediT roles below with all authors before submission.
\authorcontributions{Conceptualization, methodology, software, validation, formal analysis, investigation, data curation, writing---original draft preparation, writing---review and editing, visualization, supervision, and project administration: all authors. All authors have read and agreed to the published version of the manuscript.}

\funding{This research received no external funding.}
\institutionalreview{Not applicable.}
\informedconsent{Not applicable.}
\dataavailability{The repository exposes the implementation and non-sensitive rule assets. The legacy evaluation lacks an immutable public manifest; a sanitized corpus, sidecar labels, experiment configuration, and hashed result bundle are planned as supplementary artifacts after license and disclosure review. Restricted commercial-module inputs cannot be redistributed and may be available only subject to permission.}
\conflictsofinterest{The authors declare no conflicts of interest.}

\abbreviations{Abbreviations}{
The following abbreviations are used in this manuscript:
\\
\noindent
\begin{tabular}{@{}ll}
AI & Artificial Intelligence \\
API & Application Programming Interface \\
AST & Abstract Syntax Tree \\
FN & False Negative \\
FP & False Positive \\
KCMVP & Korean Cryptographic Module Validation Program \\
KISA & Korea Internet \& Security Agency \\
LEA & Lightweight Encryption Algorithm \\
LLM & Large Language Model \\
RAG & Retrieval-Augmented Generation \\
TP & True Positive
\end{tabular}
}

\begin{adjustwidth}{-\extralength}{0cm}
\reftitle{References}
% Pre-generated bibliography for fast, reliable Overleaf compilation.
% The editable BibTeX database remains available as references.bib.
\input{references_generated}
\PublishersNote{}
\end{adjustwidth}
\end{document}
```

## 00abstract.tex

```latex
\abstract{The Korean Cryptographic Module Validation Program (KCMVP) is a national certification system that verifies cryptographic modules deployed in government and public institutions. Its review and supplementation cycles motivate tools that can identify candidate issues before submission. We propose a framework combining rule-based detection (L1), RAG-based evidence retrieval (L2), and LLM-based re-evaluation (L3). The current repository snapshot encodes 161 YAML assets: 92 code-analysis rules, 65 document rules, and four traceability rules executed separately. A legacy author-constructed evaluation on 128 LEA-based labeled cases reported 128 detections and removal of 9 among 46 author-labeled FP candidates without removing a labeled violation. Because that run predates immutable experiment manifests, these figures are preliminary legacy observations rather than reproducible estimates for the current snapshot. Independent labeling, controlled L2 ablation, and cross-algorithm evaluation are required before broader generalization.}

\keyword{KCMVP; artificial intelligence; large language model; pre-certification; retrieval-augmented generation; rule-based detection; abstract syntax tree; multi-layer analysis; semantic verification; pre-conformance inspection}
```

## 01introduction.tex

```latex
%====================================================================
\section{Introduction}
\label{sec:intro}

The Korean Cryptographic Module Validation Program (KCMVP~\cite{nis2025}), administered by the National Intelligence Service (NIS) and the Korea Internet \& Security Agency (KISA), is a mandatory statutory certification system for cryptographic modules deployed in the information systems of government and public institutions. Under the Electronic Government Act, all cryptographic modules operated on the national network of administrative agencies and the like must pass KCMVP validation, and this functions as a core pillar that supports the Republic of Korea's national cybersecurity infrastructure.

The KCMVP validation procedure broadly consists of four stages: validation application, document review, technical review (main examination), and final deliberation/certification~\cite{nis2025}.

In particular, at the technical review stage, the validator analyzes the source code and rigorously inspects the correctness of the cryptographic algorithm implementation, compliance with secure coding practices, and the consistency between the source code and the submitted documents.

One practical source of delay is the supplement-request cycle. When a defect is found, the applicant must correct the issue, repeat the relevant tests, and resubmit. Repeated cycles can delay completion and add remediation cost. To our knowledge, publicly documented tools do not jointly inspect source code, submitted documents, and their traceability against KCMVP-specific requirements before official submission.

To fill this gap, in this study we propose a hybrid pre-certification tool -- combining rule-based static inspection with Retrieval-Augmented Generation (RAG) and Large Language Models -- intended to help identify potential KCMVP issues before official review. The system is an auxiliary prototype and does not replace official validation; this study does not measure a reduction in actual supplementation cycles.

\noindent\textbf{The prototype is available on GitHub:}\\
\url{https://github.com/SuBeen-Cho/KCMVP-Compliance-Tool.git}

\subsection{Main Contributions}

\textbf{Proposal of a hybrid three-stage validation pipeline.}
We propose a funnel-shaped three-stage architecture that combines rule-based static detection (L1), evidence retrieval and augmentation (L2), and generative-model-based final decision (L3). In a legacy author-constructed evaluation, 128 labeled cases were reported as detected, and L3 removed 9 of 46 candidates labeled as false positives (19.6\%), with no author-labeled TP removed; the reported precision and F1-score were 77.6\% and 87.4\%. That run lacks an immutable manifest tying it to the current repository snapshot, so these figures are retained as provisional feasibility evidence rather than a general performance estimate.

\textbf{Systematized KCMVP inspection rule set and domain-specific false-positive mitigation.}
We encode 161 YAML rule assets across five categories (common security, algorithms, modes of operation, documentation, and traceability), comprising 92 code-oriented rules, 65 document rules, and four traceability rules. The present implementation and quantitative evaluation are LEA-centered; support for other KCMVP algorithms is treated as future work. A commercial-module case study is retained as a qualitative stress test rather than as an independently labeled FP benchmark.

\textbf{Simultaneous validation of source code and submitted documents.}
By taking as input and preprocessing not only the source code but also the submitted documents (design, configuration management, testing, etc.) that are mandatorily required during the cryptographic module validation process, this tool enables code rules and document rules to be inspected in parallel within the same pipeline. Through this, the system goes beyond static analysis of code alone and also encompasses rule-based inspection of the document deliverables required by the validation authority.
```

## 02background.tex

```latex
%====================================================================
\section{Background}
\label{sec:background}

\subsection{Overview of the KCMVP System}

The Korean Cryptographic Module Validation Program (KCMVP) is a national certification system operated under Article~9, Paragraphs~2 and~3 of the Cyber Security Work Regulations~\cite{cybersec2024} and Article~69 of the Enforcement Decree of the Electronic Government Act~\cite{egov2025}. It is the domestic counterpart to the United States' CMVP (FIPS 140-2/3)~\cite{fips1402,fips1403}, with a similar validation framework and security-requirements structure but differing in the list of approved algorithms and the testing procedures. The purpose of this program is to objectively verify whether the cryptographic modules used in the information systems of government and public institutions satisfy national security requirements. The targets of KCMVP validation are cryptographic modules intended to protect non-classified business data, and they may be implemented as software, hardware, firmware, or a combination thereof.

KCMVP is based on KS~X ISO/IEC 19790 (Security Requirements for Cryptographic Modules)~\cite{ks19790} and KS~X ISO/IEC 24759 (Test Requirements for Cryptographic Modules)~\cite{ks24759}, and classifies security levels into four grades, from Level~1 to Level~4. This study targets Level~1 software modules, which are the most common subjects of domestic cryptographic module certification.

The core functions that a cryptographic module must provide are the four security services of confidentiality, integrity, authentication, and non-repudiation, and the KCMVP-approved algorithms include LEA~\cite{lea2014}, the Korean national standard, as well as algorithms such as AES~\cite{aes2023} and SEED~\cite{seed2005}. This study selects LEA as a bounded initial analysis target; it does not infer prevalence or claim cross-algorithm generalization from the present evaluation.

\subsection{KCMVP Adoption Criteria and Validation Procedure}

Products for which KCMVP certification is mandatorily required fall broadly into three types: (i)~information protection systems (firewalls, VPNs, intrusion detection systems, etc.), (ii)~quantum cryptographic communication equipment, and (iii)~products in which cryptography is the main function. In this respect, unlike hardware and firmware, software modules undergo frequent code modifications, and depending on the scope of change when applying functional improvements or security patches, either full re-validation or partial re-examination is required. This produces recurring temporal and financial burdens even after certification has been obtained.

The KCMVP validation procedure proceeds in the following four stages:

\begin{enumerate}
\item \textbf{Validation Application:} The cryptographic module developer organization applies to the testing agency (KISA) for validation, submitting the source code, detailed design specification, test specification, configuration management document, and operator/user manual.
\item \textbf{Document Review:} The testing agency verifies the formal completeness of the submitted documents and whether they satisfy basic requirements.
\item \textbf{Technical Review} (Main Examination): The testing agency rigorously tests the correctness of the algorithm implementation in the source code, compliance with secure coding practices, and the traceability between code and documents.
\item \textbf{Final Deliberation and Certification:} The validation authority (NIS) finally confirms whether the test results meet the standards and then issues the certificate.
\end{enumerate}

The process can be lengthy, and supplement requests during technical review can add repeated correction, retesting, and resubmission work. This creates a practical motivation for an auxiliary pre-certification tool; the present study does not measure certification-time or cost reduction in operational deployments.

\subsection{LLM- and RAG-based Technologies}

A Large Language Model (LLM) is a neural network model pre-trained on massive amounts of code and natural language data, and it is used in a variety of software analysis tasks such as code understanding, pattern recognition, and natural language generation~\cite{llmsurvey2023}.

Google's Gemini 2.5 Flash-Lite~\cite{gemini25}, used at the L3 stage of this paper, supports long context inputs and was selected for prototype L3 decisions over code fragments and supporting evidence.

Retrieval-Augmented Generation (RAG) is a methodology that combines external knowledge-based evidence with the responses of LLMs~\cite{rag2020}. Since LLMs may not have included domain-specific regulations such as KCMVP guidelines in their pre-training data, a RAG architecture that dynamically injects external knowledge is needed. In this system, the Retrieval part of RAG is performed at the L2 stage to search the KCMVP guideline articles, and the retrieved evidence is inserted into the Gemini prompt context at the L3 stage.

\subsection{Related Work}

Table~\ref{tab:related} compares the proposed system with related prior work along five functional dimensions. The comparison targets are representative prior studies on static-analysis-based detection of cryptographic misuse (CryptoGuard, CogniCrypt) and the algorithm testing automation tool of the U.S. CMVP ecosystem (CAVP).

CryptoGuard~\cite{cryptoguard2019} leverages an inter-procedural slicing technique to detect 16 categories of cryptographic API misuse in Java. CogniCrypt~\cite{cognicrypt2017} provides IDE-integrated inspection for the use of the Java Cryptography Architecture (JCA). Both tools have demonstrated the effectiveness of automated cryptographic-code inspection, but they do not address KCMVP-specific requirements or LEA.

The Cryptographic Algorithm Validation Program (CAVP)~\cite{cavp}, operated by the U.S. NIST, is an algorithm testing automation tool focused on verifying the correctness of test vectors. It verifies the mathematical correctness of algorithm implementations based on publicly available test vectors, but does not provide functionality for analyzing implementation context in the source code or for verifying document traceability. Korea's existing KCMVP pre-certification system is likewise limited to test-vector accuracy testing~\cite{nsrguide2023}. Thus, while existing studies have demonstrated the feasibility of automating cryptographic-code inspection, no tool exists that simultaneously supports the incorporation of KCMVP-specific requirements, LLM-based semantic decision-making, and automated traceability between source code and documents. This study proposes a three-stage hybrid pipeline that integrates these three functions.

\begin{table}[t]
\centering
\caption{Comparative analysis with related prior work. $\checkmark$ = supported, $\times$ = not supported.}
\label{tab:related}
\small
\setlength{\tabcolsep}{4pt}
\renewcommand{\arraystretch}{1.08}

\begin{tabular*}{\textwidth}{@{\extracolsep{\fill}} l l c c c c c @{}}
\toprule
System & Target
& \makecell{Crypto.\\Insp.}
& \makecell{LLM\\decision}
& \makecell{Doc.\\Insp.}
& \makecell{Trace-\\ability}
& \makecell{Evidence\\matching} \\
\midrule
CryptoGuard~\cite{cryptoguard2019} & Java API      & $\checkmark$ & $\times$     & $\times$     & $\times$     & $\times$ \\
CogniCrypt~\cite{cognicrypt2017}   & Java JCA      & $\checkmark$ & $\times$     & $\times$     & $\times$     & $\times$ \\
CAVP~\cite{cavp}                   & Test vectors  & $\checkmark$ & $\times$     & $\times$     & $\times$     & $\times$ \\
Proposed system                    & KCMVP         & $\checkmark$ & $\checkmark$ & $\checkmark$ & $\checkmark$ & $\checkmark$ \\
\bottomrule
\end{tabular*}
\end{table}
```

## 04prototype.tex

```latex
%====================================================================
\section{Prototype Implementation}
\label{sec:impl}

\subsection{Implementation Environment}

This interface is designed with the purpose of enabling users to clearly specify their analysis settings and submission materials and then review the entire pipeline's outputs without missing anything. That is, the interface treats code and submitted documents as equal validation targets; separates the roles of navigation, body, and violation information so that users can quickly verify and judge the mechanical detection results in context; and has the final report reveal the summary and details sequentially, with an emphasis on reducing the cognitive load that may arise during pre-conformance inspection and on improving readability for the user.

\subsection{Prototype Screen Layout}

\paragraph{Initial Screen.}
Fig.~\ref{fig:screen1} shows the initial screen of this pre-certification tool. The user can specify analysis conditions---such as the security level, product category, cryptographic algorithm, and mode of operation---matching the conditions of the actual test application, then submit the source code via a GitHub URL or a ZIP archive, and additionally upload PDFs by document type, including the design specification, configuration management, and test specification.

\begin{figure}[!htbp]
\centering
\caption{Initial-screen layout.}
\label{fig:screen1}
\end{figure}

\paragraph{Main Screen.}
Fig.~\ref{fig:screen2} and Fig.~\ref{fig:screen3} show the main verification screen that compares code and violations after the analysis is complete. The review screen of this system adopts a three-pane layout. The layout is arranged so that the user naturally proceeds in the following order: selecting the file to analyze from the file tree on the left, verifying the violation locations through line numbers and highlights in the central code/document viewer, and viewing the rule, severity, confirmed/candidate status, and patch notes at a glance in the violation list on the right. At this point, clicking on a violation in the list immediately jumps to its location, enhancing user convenience. A violation-count badge next to each file name allows the user to prioritize which file to view first.

\begin{figure}[H]
\centering
\caption{Main screen and panel structure.}
\label{fig:screen2}
\end{figure}

\paragraph{Final Report Screen.}
The report (see Fig.~\ref{fig:screen3}) screen summarizes confirmed violations, violation candidates, and totals as cards at the top, and divides the inspection axes---such as common security, algorithms, modes, documents, and traceability---into per-category tables, introducing an information hierarchy that lets the user first identify where failures or review needs arose before drilling down into details. Alongside output buttons such as PDF and print, the right panel additionally shows the per-source (code/document) counts as auxiliary information, and finally the AI summarizes the content so that the results can be checked at a glance.

Ultimately, an IDE-style three-pane layout was adopted to provide an integrated working environment in which the analysis target and the analysis results can be examined simultaneously.\footnote{The actual implementation video can be viewed at \url{https://www.youtube.com/watch?v=6zdJuxVIIgmE}.}

\begin{figure}[H]
\centering
\caption{Main screen and Patch Notes.}
\label{fig:screen3}
\end{figure}

Table~\ref{tab:stack} shows the main technology stack used to implement the system.

\begin{table}[b]
\centering
\caption{System implementation technology stack.}
\label{tab:stack}
\small
\begin{tabular}{@{}ll@{}}
\toprule
Component & Technology used \\
\midrule
Backend & FastAPI (Python 3.11+) \\
Frontend & React 18 + Zustand \\
C/C++ parser & libclang~\cite{libclang} + pycparser~\cite{pycparser} \\
PDF extraction & PyMuPDF~\cite{pymupdf} + pdfplumber~\cite{pdfplumber} + MarkItDown~\cite{markitdown} \\
LLM & Gemini 2.5 Flash Lite~\cite{gemini25}; Gemini 2.0 Flash Vision OCR~\cite{gemini20flash} \\
Vector store & ChromaDB \\
Rule format & YAML \\
\bottomrule
\end{tabular}
\end{table}
```

## 05evaluation.tex

```latex
%====================================================================
\section{Evaluation}
\label{sec:eval}

The evaluation of this study was carried out on the web prototype implemented in Sect.~\ref{sec:impl}.

The initial evaluation uses an author-labeled dataset derived through analysis of KISA LEA code. The quantitative evaluation in Sect.~\ref{subsec:experiment} uses synthetic data with intentionally inserted violations rather than certified production modules.

\subsection{Experimental Evaluation}
\label{subsec:experiment}

\paragraph{Test Dataset.}
Based on a C-language implementation of LEA~\cite{lea2014} and a validated module's security policy~\cite{ncsc2026}, the authors constructed seven code-ZIP and design-PDF pairs with intentionally injected violations. They cover CBC/CTR modes, key management, zeroization, random-number generation, the LEA key schedule, round function, and MCT loop. The 128 cases are author-reviewed labels; independent annotation has not yet been completed.

\paragraph{Code Violation Detection Performance.}
This initial evaluation characterizes detection on the author-constructed dataset and the L3 filtering behavior recorded in a legacy run. Recall measures missed labeled violations, while the filtering indicator records removed author-labeled FP candidates and removed labeled TPs. It does not directly measure human review time. Table~\ref{tab:results} reports the legacy values; the original run lacks an immutable manifest tying it to the current repository snapshot.

\begin{table}[t]
\centering
\caption{Code violation detection performance (Sets 1--7, based on 128 GT cases).}
\label{tab:results}
\small
\begin{tabular}{@{}ll@{}}
\toprule
Metric & Result \\
\midrule
True Positive (TP) & 128 cases \\
False Negative (FN) & 0 cases \\
Recall & 100\% \\
L1-stage False Positive candidates & 46 cases \\
L3 filtering: FP removal & 9/46 (19.6\%) \\
Author-labeled TPs removed by L3 & 0 cases \\
Final False Positive (FP) & 37 cases \\
Precision & 77.6\% \\
F1-score & 87.4\% \\
\bottomrule
\end{tabular}
\end{table}

On this dataset, the legacy run recorded all 128 labeled code cases and L3 removed 9 of 46 author-labeled FP candidates without removing an author-labeled TP. These observations motivate the layered design but do not isolate L2 or establish reduced human review effort. Document-rule outputs were inspected qualitatively; no independently labeled document confusion matrix is claimed. Because \texttt{missing}-type rules judge absence as a violation, delegation to other files can still yield false candidates.

\paragraph{Case Study on a Real Cryptographic Module.}
In addition to the synthetic dataset, we inspected a commercial cryptographic module developed for KCMVP submission. A reproducibility audit found that the earlier draft mixed two counting scopes: the archive contains 34 C files with 11,983 physical lines, whereas including 25 header files produces 59 C/H files with 14,511 physical lines. The earlier value of 0.58 cases/KLOC therefore combined a C-only numerator/denominator with a C/H description. Moreover, saved legacy runs contained different candidate counts and lacked immutable code/input/prompt manifests. We consequently withdraw the candidate-frequency value from the performance claims and retain this dataset only as a qualitative case study until a manifest-bound rerun and independent labeling are completed. Certification status alone is not used to label every static-analysis candidate as an FP.

\begin{table}[t]
\centering
\caption{Re-audited scope of the commercial-module case study.}
\label{tab:blind}
\small
\begin{tabular}{@{}ll@{}}
\toprule
Metric & Result \\
\midrule
C source scope & 34 files / 11,983 physical LOC \\
C and header scope & 59 files / 14,511 physical LOC \\
Candidate count & Withheld pending canonical rerun \\
Candidate frequency & Not reported \\
Ground-truth status & Independent labeling pending \\
\bottomrule
\end{tabular}
\end{table}

Accordingly, this case study cannot presently establish a real-world FP rate or generalization performance. It remains useful for identifying parser, naming, and cross-file limitations, but not for estimating predictive accuracy.

Illustrative candidate classes observed in legacy runs, but not independently labeled, include residual-data clearing items (COM-001). Even when source code contains zeroization, a compiler may eliminate it as a dead store. Future intermediate-representation or symbolic-execution analysis should account for compiler optimization.

Items corresponding to the absence of test infrastructure do not surface in functional behavior tests and are currently detected only through rule-based checks. This system implements a basic level of traceability verification, but, because of its reliance on regular-expression-based function extraction, omissions appear to have occurred for non-standard naming conventions and macro-wrapped functions. It is expected that detection accuracy for this type of issue can be improved by combining it with file-tree-structure analysis and reinforcing it with a complete AST-based implementation.

\subsection{Limitations Analysis}

\begin{enumerate}
\item \textbf{TRC traceability verification's reliance on regular expressions.} Because matching depends mainly on regular expressions and naming rules for whether header function declarations or in-document references exist, there is a risk of omissions and misidentifications for non-standard naming conventions, macro-wrapped APIs, and the like.

\item \textbf{The gap between the evaluation dataset and real-world environments.} Since this evaluation, centered on publicly available and synthetic materials, does not fully represent the scale or coding practices of commercial codebases that actually apply for KCMVP certification, a follow-up evaluation that utilizes actual confidential data through cooperation with certification authorities is required.

\item \textbf{Author-constructed Ground Truth and algorithm scope.} The 128 labeled cases were constructed and reviewed by the authors and are centered on LEA. Independent blinded annotation and algorithm-specific test sets for AES, SEED, and other KCMVP algorithms are required before the reported recall and precision can be generalized.

\item \textbf{Unisolated contribution of L2.} The reported end-to-end results do not independently quantify the effect of RAG evidence. A controlled paired comparison between L1+L3 without retrieved evidence and L1+L2+L3, holding candidates, prompts, model parameters, and repetitions constant, is required. Until then, L2 is supported as an evidence-provision mechanism rather than as a demonstrated accuracy improvement.

\item \textbf{Threshold calibration and operational cost.} The $65$--$74$ re-evaluation interval was selected heuristically. A calibration and threshold-sensitivity analysis is required together with manifest-bound measurements of elapsed time, API calls, tokens, and pricing snapshots. Legacy telemetry is not promoted to a final cost claim because it cannot be tied to an immutable experiment version.

\item \textbf{Evidence extraction limitations due to document expression diversity.} Security policy documents and design specifications may describe identical requirements using different terminology and structures depending on the authoring organization, format, and version. In particular, for documents centered on tables, appendices, scanned images, and abbreviations, context may become fragmented or inter-item relationships may be lost during the PDF text extraction process. In such cases, the system may fail to retrieve relevant evidence sufficiently, or may link sentences that are semantically adjacent but are not direct evidence. Accordingly, future work requires reinforcement of document structure recognition, table-level parsing, and per-requirement evidence normalization techniques.
\end{enumerate}
```

## 06conclusion.tex

```latex
%====================================================================
\section{Conclusion}
\label{sec:conclusion}

In this study, we proposed and implemented a hybrid framework for KCMVP pre-compliance inspection that ties rule-based static analysis (L1), RAG-based guideline-evidence attachment (L2), and LLM-based semantic re-evaluation (L3) into a single funnel-shaped pipeline. The system applies rules---covering common security, LEA implementation constraints, multiple modes of operation, submission-document formats, and code--document traceability---that are formalized in YAML, and through the KCMVP guideline mapping linked to the rule identifiers, it allows evidence to be attached to the interpretation of the results.

Through the initial LEA-centered prototype evaluation, we observed the complementary behavior in which deterministic L1 provides broad candidate coverage and L3 can remove some labeled false positives through contextual reasoning. The multi-layered evidence retrieval at L2 attaches standards and guideline citations to violation items, but its independent effect on decision accuracy has not yet been established. In addition, the system incorporates practical mechanisms tailored to the non-standard nature of real code, such as preprocessing/parsing fallbacks, domain-oriented false-positive mitigation, and multi-stage detection of common-security rules.

On the other hand, this system still remains a pre-certification auxiliary tool. Some of the AST rules rely on a regex fallback, the traceability verification has limitations centered on declaration and text matching, and the experiments were conducted primarily on publicly available and synthetic materials, so they cannot be regarded as representative of the entire set of actually submitted modules. Future work is as follows.

\begin{itemize}
\item \textbf{Advancement of AST Analysis:} Migrate the rules that currently rely on fallbacks to structural analysis by utilizing pycparser, tree-sitter, and similar tools.

\item \textbf{Strengthening of Traceability Verification:} Extend the extraction and matching logic to encompass macros, multi-line declarations, and API mappings listed in design-specification tables.

\item \textbf{Validation on Real Data:} Conduct reproducibility evaluations using actual submission deliverables in part, through cooperation with certification authorities and industry.

\item \textbf{Expansion of Algorithm and Mode Coverage:} The current LEA-centered support is to be extended in two directions. (1)~Within block ciphers: expand the rule set to other KCMVP-approved block ciphers such as AES, SEED, and ARIA. (2)~Across cryptographic primitive types: investigate extension to hash functions (SHA-256, SHA-3, LSH, etc.) and public-key algorithms (EC-KCDSA, RSA, etc.). Hash functions require inspection items distinct from block ciphers, such as input-length restrictions, padding handling, and fixed initialization-vector verification. Public-key algorithms demand stateful, composite checks including key-length adequacy, PRNG coupling, signature-nature-verification ordering, and certificate-chain handling. In particular, because public-key operations (key generation, signing, and verification) are distributed across separate functions and files, the current single-file-centric AST analysis must be strengthened into cross-file call-flow analysis.

\item \textbf{L3 Operational Optimization:} Study the cost--quality balance, including transitions to local and open-source LLMs, call limits, batching strategies, and regression testing.
\end{itemize}

Building on these directions, we expect that this work can lead to subsequent standardization and tool development aimed at reducing the review costs entailed by certification preparation.
```

