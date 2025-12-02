# 💻 네트워크 프로그래밍 기말과제: TFTP 클라이언트 구현

## 1. 개요 및 목적

본 클라이언트는 **Python 3**의 Socket API를 이용하여 **TFTP (Trivial File Transfer Protocol, RFC 1350)** 클라이언트 기능을 구현합니다. 작성된 클라이언트는 과제 환경인 FTP 서버 **tftpd-hpa**와 프로토콜에 따라 동작하도록 설계되었습니다.

## 2. 구현 기능 및 특징

* **파일 전송 기능:** 파일을 다운로드 (**get**)하거나 업로드 (**put**)할 수 있습니다.
* **전송 모드:** 'octet' 모드만 지원합니다.
* **호스트 지정:** 서버 주소를 도메인 이름 (예: `genie.pcu.ac.kr`)이나 IP 주소 (예: `203.250.133.88`)로 지정할 수 있습니다.
* **포트 설정:** 서버 포트가 기본 포트인 `69`가 아닐 경우, `-p` 옵션을 사용하여 포트를 지정할 수 있습니다.
* **프로토콜 처리:** TFTP의 기본 패킷 구조 (RRQ, WRQ, DATA, ACK, ERROR)를 준수합니다.

## 3. 프로그램 실행 방법 (Usage)

클라이언트는 명령줄 인수를 통해 실행되며, 실행 파일은 `mytftp.py`로 가정합니다.

**실행 형식:**
```bash
$ python mytftp.py host [-p port] [get|put] filename



import socket
import sys
import os
import random

# TFTP Opcodes (RFC 1350)
OPCODE_RRQ = 1  # Read Request (다운로드)
OPCODE_WRQ = 2  # Write Request (업로드)
OPCODE_DATA = 3 # Data
OPCODE_ACK = 4  # Acknowledgment
OPCODE_ERROR = 5 # Error

# 기본 설정 상수
DEFAULT_PORT = 69   # TFTP 표준 포트 (서버의 초기 요청 수신 포트)
TIMEOUT = 5         # 소켓 타임아웃 설정 (초)
MAX_RETRIES = 5     # 최대 재시도 횟수 (서버 응답이 없을 경우)
BLOCK_SIZE = 512    # TFTP 데이터 블록 크기 (512바이트)

def parse_args(args):
    """
    명령줄 인수를 파싱하여 host, port, operation, filename을 추출합니다.
    """
    if len(args) < 4:
        raise ValueError("사용 형식: mytftp host [-p port] [get|put] filename")

    host = args[1] 
    port = DEFAULT_PORT
    
    # -p 옵션 처리: 포트 지정 기능 구현
    if '-p' in args:
        try:
            p_index = args.index('-p')
            port = int(args[p_index + 1])
            # -p와 포트 번호를 인자 리스트에서 제거하여 이후 로직 단순화
            args.pop(p_index)
            args.pop(p_index) 
        except (ValueError, IndexError):
            raise ValueError("-p 옵션 사용 오류: 유효한 포트 번호를 입력하세요.")

    # ... (인수 처리 로직 생략) ...

    operation = args[2].lower()
    filename = args[3]

    if operation not in ['get', 'put']:
        raise ValueError("유효하지 않은 operation: 'get' 또는 'put'이어야 합니다.")

    return host, port, operation, filename

def create_tftp_packet(opcode, *args):
    """
    TFTP 요청/응답 패킷을 생성합니다.
    """
    if opcode == OPCODE_RRQ or opcode == OPCODE_WRQ:
        # RRQ/WRQ 패킷 생성: 파일 이름과 모드('octet') 포함
        filename, mode = args
        return opcode.to_bytes(2, byteorder='big') + \
               filename.encode('ascii') + b'\x00' + \
               mode.encode('ascii') + b'\x00'
    elif opcode == OPCODE_ACK:
        # ACK 패킷 생성: 수신 확인을 위한 블록 번호 포함
        block_num = args[0]
        return opcode.to_bytes(2, byteorder='big') + \
               block_num.to_bytes(2, byteorder='big')
    elif opcode == OPCODE_DATA:
        # DATA 패킷 생성
        block_num, data = args
        return opcode.to_bytes(2, byteorder='big') + \
               block_num.to_bytes(2, byteorder='big') + \
               data
    return b''

def handle_tftp_error(data):
    """
    TFTP ERROR 패킷을 파싱하고 과제 요구사항의 특정 오류를 처리합니다.
    """
    if len(data) < 5 or data[0:2] != OPCODE_ERROR.to_bytes(2, byteorder='big'):
        print("수신된 패킷이 ERROR 형식이 아닙니다.")
        return

    error_code = int.from_bytes(data[2:4], byteorder='big')
    error_message = data[4:-1].decode('ascii')
    
    print(f"🔥 TFTP 오류 발생: 에러 코드 {error_code}")
    print(f"   메시지: {error_message}")
    
    # 과제 요구사항 처리: Error Code 1 (File not found)
    if error_code == 1:
        print("   -> File not found 오류입니다.")
    # 과제 요구사항 처리: Error Code 6 (File already exists)
    elif error_code == 6:
        print("   -> File already exists 오류입니다.")

def tftp_get(sock, server_address, filename):
    """
    TFTP 'get' (파일 다운로드) 작업을 수행합니다.
    """
    # 1. RRQ 패킷 생성 및 전송 (재시도 로직 적용)
    request_packet = create_tftp_packet(OPCODE_RRQ, filename, 'octet')
    
    try:
        with open(filename, 'wb') as f:
            block_number = 1
            retries = 0
            
            while retries < MAX_RETRIES:
                try:
                    sock.sendto(request_packet, server_address)
                    data, server_address_new = sock.recvfrom(BLOCK_SIZE + 4)
                    
                    # 서버의 새로운 포트 (TID)로 통신 주소 변경
                    server_address = server_address_new 
                    break 
                except socket.timeout:
                    retries += 1
                    # 과제 요구사항: RRQ 후 서버 응답이 없을 경우 처리
                    if retries == MAX_RETRIES:
                        print("🚫 서버 응답이 없습니다. TFTP 다운로드 실패.")
                        return

            # 데이터 수신 및 ACK 전송 루프
            while True:
                opcode = int.from_bytes(data[:2], byteorder='big')
                
                if opcode == OPCODE_ERROR:
                    handle_tftp_error(data)
                    return
                
                if opcode == OPCODE_DATA:
                    current_block = int.from_bytes(data[2:4], byteorder='big')
                    data_chunk = data[4:]
                    
                    # 블록 순서 확인 및 데이터 쓰기
                    if current_block == block_number:
                        f.write(data_chunk)
                        
                        # ACK 패킷 생성 및 전송 (수신 확인)
                        ack_packet = create_tftp_packet(OPCODE_ACK, block_number)
                        sock.sendto(ack_packet, server_address)
                        
                        # 전송 완료 조건: 데이터 길이가 512바이트 미만
                        if len(data_chunk) < BLOCK_SIZE:
                            print(f"✅ 파일 다운로드 성공: {filename}")
                            break
                        
                        block_number += 1
                        # 다음 데이터 블록 수신 대기
                        data, server_address = sock.recvfrom(BLOCK_SIZE + 4)
                    
                    # 중복 수신된 블록에 대해서는 ACK 재전송
                    elif current_block < block_number:
                        ack_packet = create_tftp_packet(OPCODE_ACK, current_block)
                        sock.sendto(ack_packet, server_address)
                        data, server_address = sock.recvfrom(BLOCK_SIZE + 4)
                    # ... (미래 블록 수신 등 복잡 오류 처리 생략)

    except Exception as e:
        print(f"🚫 다운로드 중 예상치 못한 오류 발생: {e}")


def tftp_put(sock, server_address, filename):
    """
    TFTP 'put' (파일 업로드) 작업을 수행합니다.
    """
    # 0. 로컬 파일 존재 확인 및 크기 획득
    try:
        if not os.path.exists(filename):
            print(f"🚫 업로드 실패: 로컬 파일 {filename}을(를) 찾을 수 없습니다.")
            return
        file_size = os.path.getsize(filename)
    except Exception as e:
        print(f"🚫 파일 접근 오류: {e}")
        return

    # 1. WRQ 패킷 생성 및 전송 (재시도 로직 적용)
    request_packet = create_tftp_packet(OPCODE_WRQ, filename, 'octet')

    retries = 0
    while retries < MAX_RETRIES:
        try:
            sock.sendto(request_packet, server_address)
            data, server_address_new = sock.recvfrom(BLOCK_SIZE + 4)
            # 서버의 새로운 포트 (TID)로 통신 주소 변경
            server_address = server_address_new 
            break 
        except socket.timeout:
            retries += 1
            # 과제 요구사항: WRQ 후 서버 응답이 없을 경우 처리
            if retries == MAX_RETRIES:
                print("🚫 서버 응답이 없습니다. TFTP 업로드 실패.")
                return

    # 첫 응답 확인: ACK 0 또는 ERROR
    opcode = int.from_bytes(data[:2], byteorder='big')
    if opcode == OPCODE_ERROR:
        handle_tftp_error(data)
        return
    
    # ACK 0 확인 (WRQ에 대한 서버의 허가)
    if opcode != OPCODE_ACK or int.from_bytes(data[2:4], byteorder='big') != 0:
        print(f"🚫 예상치 못한 첫 응답.")
        return

    # 2. 파일 데이터 전송 시작 (ACK 0을 받은 후 Block 1부터 시작)
    try:
        with open(filename, 'rb') as f:
            block_number = 1
            
            while True:
                data_chunk = f.read(BLOCK_SIZE) # 512 바이트씩 파일 읽기
                
                # 3. DATA 패킷 생성 및 전송 (재시도 로직 적용)
                data_packet = create_tftp_packet(OPCODE_DATA, block_number, data_chunk)
                
                retries = 0
                while retries < MAX_RETRIES:
                    try:
                        sock.sendto(data_packet, server_address)
                        # 서버 응답 (ACK) 수신
                        data, server_address = sock.recvfrom(BLOCK_SIZE + 4)
                        break 
                    except socket.timeout:
                        retries += 1
                        # 타임아웃 발생 시 재전송 (재시도)
                
                if retries == MAX_RETRIES:
                    print("🚫 서버 응답이 없습니다. TFTP 업로드 실패.")
                    return

                # 수신된 응답 확인 (ACK 또는 ERROR)
                response_opcode = int.from_bytes(data[:2], byteorder='big')
                
                if response_opcode == OPCODE_ERROR:
                    handle_tftp_error(data)
                    return
                
                if response_opcode == OPCODE_ACK:
                    ack_block = int.from_bytes(data[2:4], byteorder='big')
                    
                    # 예상한 블록 번호의 ACK인지 확인
                    if ack_block == block_number:
                        # 전송 완료 조건: 마지막 블록의 크기가 512바이트 미만
                        if len(data_chunk) < BLOCK_SIZE:
                            print(f"✅ 파일 업로드 성공: {filename} ({file_size} bytes)")
                            return 
                        
                        block_number += 1 # 다음 블록으로 진행
                    
                    # ... (이전 블록 ACK 수신 등 복잡 오류 처리 생략)
    
    except Exception as e:
        print(f"🚫 업로드 중 예상치 못한 오류 발생: {e}")


def main():
    """
    메인 함수: 명령줄 인수를 처리하고 TFTP 작업을 시작합니다.
    """
    try:
        host, port, operation, filename = parse_args(sys.argv)
        
        # UDP 소켓 생성 및 타임아웃 설정
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT) 
        
        # 호스트 주소 변환 (도메인 이름 -> IP 주소)
        server_ip = socket.gethostbyname(host)
        server_address = (server_ip, port)
        
        print(f"⚙️ TFTP 클라이언트 시작")
        print(f"   서버: {host} ({server_ip}), 포트: {port}")

        if operation == 'get':
            tftp_get(sock, server_address, filename)
        elif operation == 'put':
            tftp_put(sock, server_address, filename)

    except ValueError as e:
        print(f"❌ 인수 오류: {e}")
        # ... (사용 예시 출력 생략)
    except socket.gaierror:
        print(f"❌ 호스트 오류: '{host}'에 해당하는 IP 주소를 찾을 수 없습니다.")
    except Exception as e:
        print(f"❌ 심각한 오류 발생: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    if sys.argv[0].endswith('.py'):
        sys.argv[0] = 'mytftp'
    main()