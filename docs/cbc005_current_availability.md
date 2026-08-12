# CBC-005 현재 5건 관찰 가용성

현 후보 5건의 lexical 형태는 로깅 3건, 상수 정의만 있는 경우 2건이다. 상수 정의 2건은 공식 안내서의 padding error code 예시와 충돌하므로 취약점 증거가 아니다. 로깅 3건도 전체 서비스 경계·외부 관찰·타이밍·MAC 검증 순서가 없으면 semantic proof가 아니다. 관련 authenticated 지표는 0/5, 결과는 5/5 unknown, API 0, production authorization 0이다.
