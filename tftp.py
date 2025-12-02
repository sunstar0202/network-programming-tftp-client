import socket
import argparse
import sys
import os
from struct import pack
import random

DEFAULT_PORT = 69
BLOCK_SIZE = 512
DEFAULT_TRANSFER_MODE = 'octet'
TIME_OUT = 3.0
MAX_TRY = 5

OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}
ERROR_CODE = {
    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user."
}


def create_request_packet(opcode_type, filename, mode):
    """RRQ 또는 WRQ 패킷을 생성합니다."""

    format_str = f'>h{len(filename)}sB{len(mode)}sB'
    return pack(format_str, OPCODE[opcode_type], bytes(filename, 'utf-8'),
                0, bytes(mode, 'utf-8'), 0)


def send_ack(sock, seq_num, server_address):
    """ACK 패킷을 생성하고 전송합니다."""

    format_str = f'>hh'
    ack_message = pack(format_str, OPCODE['ACK'], seq_num)
    sock.sendto(ack_message, server_address)



def handle_error(data):
    """ERROR 패킷을 파싱하고 오류 메시지를 출력합니다."""
    error_code = int.from_bytes(data[2:4], byteorder='big')
    error_message = data[4:-1].decode('utf-8')
    print(f'🔥 TFTP 오류 발생: 에러 코드 {error_code}')
    print(f'   메시지: {error_message}')

    #  에러 코드 처리
    if error_code == 1:
        print("   -> File not found 오류입니다.")
    elif error_code == 6:
        print("   -> File already exists 오류입니다.")


def tftp_get(sock, filename, server_address):
    """TFTP 'get' (다운로드) 작업을 수행합니다."""
    print(f"⬇️ 파일 다운로드 요청: {filename}")

    request_packet = create_request_packet('RRQ', filename, DEFAULT_TRANSFER_MODE)

    # RRQ 전송 및 응답 대기 루프 (재시도 로직)
    server_tid = server_address
    retries = 0
    while retries < MAX_TRY:
        try:
            sock.sendto(request_packet, server_tid)
            data, server_tid = sock.recvfrom(BLOCK_SIZE + 4)
            break
        except socket.timeout:
            retries += 1
            if retries == MAX_TRY:
                 # RRQ 응답 없을 경우 처리
                print("🚫 서버 응답이 없습니다. TFTP 다운로드 실패.")
                sys.exit()

    # 데이터 수신 및 ACK 전송 루프
    expected_block_number = 1

    with open(filename, 'wb') as file:
        while True:
            # 패킷 확인 (timeout 이후 재시도 불필요, 이미 data가 들어와 있음)
            opcode = int.from_bytes(data[:2], 'big')

            if opcode == OPCODE['ERROR']:
                handle_error(data)
                break

            if opcode == OPCODE['DATA']:
                block_number = int.from_bytes(data[2:4], 'big')
                file_block = data[4:]

                if block_number == expected_block_number:
                    file.write(file_block)
                    send_ack(sock, block_number, server_tid)  # ACK 전송

                    if len(file_block) < BLOCK_SIZE:
                        print(f"✅ 파일 다운로드 성공: {filename} ({os.path.getsize(filename)} bytes)")
                        break
                    expected_block_number += 1

                else:
                    # 중복 데이터 블록 수신 시, 마지막으로 성공한 ACK 재전송
                    send_ack(sock, expected_block_number - 1, server_tid)

                # 다음 데이터 블록 수신 대기 (ACK 전송 후)
                try:
                    data, server_tid = sock.recvfrom(BLOCK_SIZE + 4)
                except socket.timeout:
                    # 다음 블록 수신 중 타임아웃 발생 시 마지막 ACK 재전송 후 재시도
                    send_ack(sock, expected_block_number - 1, server_tid)
                    continue
            else:
                print(f"🚫 예상치 못한 Opcode {opcode} 수신.")
                break


def tftp_put(sock, filename, server_address):
    """TFTP 'put' (업로드) 작업을 수행합니다."""
    print(f"⬆️ 파일 업로드 요청: {filename}")

    if not os.path.exists(filename):
        print(f"🚫 업로드 실패: 로컬 파일 {filename}을(를) 찾을 수 없습니다.")
        sys.exit()

    request_packet = create_request_packet('WRQ', filename, DEFAULT_TRANSFER_MODE)
    server_tid = server_address  # 초기에는 69번 포트로 요청

    # WRQ 전송 및 ACK 0 대기 루프 (재시도 로직)
    retries = 0
    while retries < MAX_TRY:
        try:
            sock.sendto(request_packet, server_tid)
            data, server_tid = sock.recvfrom(4)  # WRQ 응답은 ACK 0 (4바이트) 또는 ERROR

            opcode = int.from_bytes(data[:2], 'big')
            block_number = int.from_bytes(data[2:4], 'big')

            if opcode == OPCODE['ERROR']:
                handle_error(data)
                sys.exit()

            if opcode == OPCODE['ACK'] and block_number == 0:
                print("   ACK 0 수신. 파일 전송 시작.")
                break

            print(f"   [Warning] 예상치 못한 응답 Opcode={opcode}, Block={block_number}")

        except socket.timeout:
            retries += 1
            if retries == MAX_TRY:
                # WRQ 응답 없을 경우 처리
                print("🚫 서버 응답이 없습니다. TFTP 업로드 실패.")
                sys.exit()

    # 데이터 전송 루프 (ACK 0을 받은 후 Block 1부터 시작)
    block_number = 1
    with open(filename, 'rb') as file:
        while True:
            data_chunk = file.read(BLOCK_SIZE)


            data_packet = pack(f'>hh{len(data_chunk)}s', OPCODE['DATA'], block_number, data_chunk)

            # DATA 전송 및 ACK 대기 루프 (재시도 로직)
            retries = 0
            while retries < MAX_TRY:
                try:
                    sock.sendto(data_packet, server_tid)
                    ack_data, server_tid = sock.recvfrom(4)

                    ack_opcode = int.from_bytes(ack_data[:2], 'big')
                    ack_block = int.from_bytes(ack_data[2:4], 'big')

                    if ack_opcode == OPCODE['ERROR']:
                        handle_error(ack_data)
                        sys.exit()

                    if ack_opcode == OPCODE['ACK'] and ack_block == block_number:
                        break  # 성공적으로 ACK 받음

                    # 중복 ACK 또는 잘못된 ACK은 무시하고 재시도

                except socket.timeout:
                    retries += 1

            if retries == MAX_TRY:
                print("🚫 서버로부터 ACK를 받지 못했습니다. 업로드 실패.")
                break


            if len(data_chunk) < BLOCK_SIZE:
                print(f"✅ 파일 업로드 성공: {filename} ({os.path.getsize(filename)} bytes)")
                break

            block_number += 1


def main():

    parser = argparse.ArgumentParser(description='TFTP client program')
    parser.add_argument(dest="host", help="Server IP address or hostname", type=str)
    parser.add_argument(dest="operation", help="get or put a file", type=str)
    parser.add_argument(dest="filename", help="name of file to transfer", type=str)
    parser.add_argument("-p", "--port", dest="port", type=int)
    args = parser.parse_args()


    try:
        server_ip = socket.gethostbyname(args.host)  # 도메인 이름 지원 추가
    except socket.gaierror:
        print(f"❌ 호스트 오류: '{args.host}'에 해당하는 IP 주소를 찾을 수 없습니다.")
        sys.exit()

    server_port = args.port if args.port is not None else DEFAULT_PORT
    server_address = (server_ip, server_port)


    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIME_OUT)

    print(f"⚙️ TFTP 클라이언트 시작")
    print(f"   서버: {args.host} ({server_ip}), 포트: {server_port}")
    print(f"   작업: {args.operation}, 파일: {args.filename}")
    print("-" * 30)


    if args.operation.lower() == 'get':
        tftp_get(sock, args.filename, server_address)
    elif args.operation.lower() == 'put':
        tftp_put(sock, args.filename, server_address)
    else:
        print("❌ 유효하지 않은 operation: 'get' 또는 'put'이어야 합니다.")

    sock.close()


if __name__ == "__main__":
    main()