import socket
import sys
import os
import random

OPCODE_RRQ = 1
OPCODE_WRQ = 2
OPCODE_DATA = 3
OPCODE_ACK = 4
OPCODE_ERROR = 5
DEFAULT_PORT = 69
TIMEOUT = 5
MAX_RETRIES = 5
BLOCK_SIZE = 512


def parse_args(args):
    """
        명령줄 인수를 파싱하여 host, port, operation, filename을 추출합니다.
        사용 형식: mytftp host [-p port] [get|put] filename
        """
    if len(args) < 4:
        raise ValueError("사용 형식: mytftp host [-p port] [get|put] filename")

    host = args[1]


    port = DEFAULT_PORT


    if '-p' in args:
        try:
            p_index = args.index('-p')
            port = int(args[p_index + 1])


            args.pop(p_index)
            args.pop(p_index)
        except (ValueError, IndexError):
            raise ValueError("-p 옵션 사용 오류: 유효한 포트 번호를 입력하세요.")


    if len(args) != 4:
        raise ValueError("사용 형식 오류: operation(get/put)과 filename을 확인하세요.")

    operation = args[2].lower()
    filename = args[3]

    if operation not in ['get', 'put']:
        raise ValueError("유효하지 않은 operation: 'get' 또는 'put'이어야 합니다.")

    return host, port, operation, filename


def create_tftp_packet(opcode, *args):
    """
    TFTP 요청 패킷(RRQ/WRQ)을 생성합니다.
    RRQ/WRQ 패킷 형식:
    | 2바이트 Opcode | 가변 File 이름 | 1바이트 0 | 가변 Mode | 1바이트 0 |
    """
    if opcode == OPCODE_RRQ or opcode == OPCODE_WRQ:
        filename, mode = args

        return opcode.to_bytes(2, byteorder='big') + \
            filename.encode('ascii') + b'\x00' + \
            mode.encode('ascii') + b'\x00'
    elif opcode == OPCODE_ACK:
        block_num = args[0]

        return opcode.to_bytes(2, byteorder='big') + \
            block_num.to_bytes(2, byteorder='big')
    elif opcode == OPCODE_DATA:
        block_num, data = args

        return opcode.to_bytes(2, byteorder='big') + \
            block_num.to_bytes(2, byteorder='big') + \
            data
    return b''


def handle_tftp_error(data):
    """
    TFTP ERROR 패킷을 파싱하여 오류 코드를 출력합니다.
    """
    if len(data) < 5 or data[0:2] != OPCODE_ERROR.to_bytes(2, byteorder='big'):
        print("수신된 패킷이 ERROR 형식이 아닙니다.")
        return


    error_code = int.from_bytes(data[2:4], byteorder='big')

    error_message = data[4:-1].decode('ascii')

    print(f"🔥 TFTP 오류 발생: 에러 코드 {error_code}")
    print(f"   메시지: {error_message}")


    if error_code == 1:
        print("   -> File not found 오류입니다.")
    elif error_code == 6:
        print("   -> File already exists 오류입니다.")


def tftp_get(sock, server_address, filename):
    """
    TFTP 'get' (파일 다운로드) 작업을 수행합니다.
    """
    print(f"⬇️ 파일 다운로드 요청: {filename}")


    request_packet = create_tftp_packet(OPCODE_RRQ, filename, 'octet')


    try:
        with open(filename, 'wb') as f:
            block_number = 1
            retries = 0


            while retries < MAX_RETRIES:
                try:
                    sock.sendto(request_packet, server_address)
                    print(f"   RRQ 전송 완료. 응답 대기...")


                    data, server_address_new = sock.recvfrom(BLOCK_SIZE + 4)


                    server_address = server_address_new
                    break
                except socket.timeout:
                    retries += 1
                    print(f"   타임아웃 발생. 재시도 중 ({retries}/{MAX_RETRIES})...")

            if retries == MAX_RETRIES:
                print("🚫 서버 응답이 없습니다. TFTP 다운로드 실패.")
                return


            while True:
                opcode = int.from_bytes(data[:2], byteorder='big')

                if opcode == OPCODE_ERROR:
                    handle_tftp_error(data)
                    return

                if opcode == OPCODE_DATA:
                    current_block = int.from_bytes(data[2:4], byteorder='big')
                    data_chunk = data[4:]


                    if current_block == block_number:
                        f.write(data_chunk)


                        ack_packet = create_tftp_packet(OPCODE_ACK, block_number)
                        sock.sendto(ack_packet, server_address)


                        block_number += 1


                        if len(data_chunk) < BLOCK_SIZE:
                            print(f"✅ 파일 다운로드 성공: {filename} ({os.path.getsize(filename)} bytes)")
                            break


                        data, server_address = sock.recvfrom(BLOCK_SIZE + 4)
                        retries = 0


                    elif current_block < block_number:

                        print(f"   [Warning] 블록 {current_block} 재수신. ACK 재전송.")
                        ack_packet = create_tftp_packet(OPCODE_ACK, current_block)
                        sock.sendto(ack_packet, server_address)
                        data, server_address = sock.recvfrom(BLOCK_SIZE + 4)
                        retries = 0
                    else:

                        print(f"   [Error] 예상치 못한 블록 번호 {current_block} 수신. 현재 {block_number}")

                        error_packet = create_tftp_packet(OPCODE_ERROR, 4, "Illegal TFTP operation")
                        sock.sendto(error_packet, server_address)
                        break

                else:
                    print(f"   [Error] 예상치 못한 Opcode {opcode} 수신.")
                    handle_tftp_error(data)
                    return

    except FileNotFoundError:
        print(f"🚫 로컬 파일 생성 오류: {filename} 파일을 쓸 수 없습니다.")
    except Exception as e:
        print(f"🚫 다운로드 중 예상치 못한 오류 발생: {e}")


def tftp_put(sock, server_address, filename):
    """
    TFTP 'put' (파일 업로드) 작업을 수행합니다.
    """
    print(f"⬆️ 파일 업로드 요청: {filename}")


    try:
        if not os.path.exists(filename):
            print(f"🚫 업로드 실패: 로컬 파일 {filename}을(를) 찾을 수 없습니다.")
            return
        file_size = os.path.getsize(filename)
    except Exception as e:
        print(f"🚫 파일 접근 오류: {e}")
        return


    request_packet = create_tftp_packet(OPCODE_WRQ, filename, 'octet')


    retries = 0
    while retries < MAX_RETRIES:
        try:
            sock.sendto(request_packet, server_address)
            print(f"   WRQ 전송 완료. 응답 대기...")


            data, server_address_new = sock.recvfrom(BLOCK_SIZE + 4)


            server_address = server_address_new
            break
        except socket.timeout:
            retries += 1
            print(f"   타임아웃 발생. 재시도 중 ({retries}/{MAX_RETRIES})...")

    if retries == MAX_RETRIES:
        print("🚫 서버 응답이 없습니다. TFTP 업로드 실패.")
        return


    opcode = int.from_bytes(data[:2], byteorder='big')
    if opcode == OPCODE_ERROR:
        handle_tftp_error(data)
        return


    if opcode != OPCODE_ACK or int.from_bytes(data[2:4], byteorder='big') != 0:
        print(f"🚫 예상치 못한 첫 응답: Opcode {opcode}, Block # {int.from_bytes(data[2:4], byteorder='big')}")
        return


    try:
        with open(filename, 'rb') as f:
            block_number = 1

            while True:
                data_chunk = f.read(BLOCK_SIZE)


                data_packet = create_tftp_packet(OPCODE_DATA, block_number, data_chunk)


                retries = 0
                received_ack = False
                while retries < MAX_RETRIES:
                    try:
                        sock.sendto(data_packet, server_address)
                        print(f"   DATA 블록 {block_number} 전송... ACK 대기.")


                        data, server_address = sock.recvfrom(BLOCK_SIZE + 4)
                        received_ack = True
                        break
                    except socket.timeout:
                        retries += 1
                        print(f"   타임아웃 발생. 블록 {block_number} 재전송 중 ({retries}/{MAX_RETRIES})...")

                if retries == MAX_RETRIES:
                    print("🚫 서버 응답이 없습니다. TFTP 업로드 실패.")
                    return


                response_opcode = int.from_bytes(data[:2], byteorder='big')

                if response_opcode == OPCODE_ERROR:
                    handle_tftp_error(data)
                    return

                if response_opcode == OPCODE_ACK:
                    ack_block = int.from_bytes(data[2:4], byteorder='big')


                    if ack_block == block_number:

                        if len(data_chunk) < BLOCK_SIZE:
                            print(f"✅ 파일 업로드 성공: {filename} ({file_size} bytes)")
                            return


                        block_number += 1
                    elif ack_block < block_number:

                        print(f"   [Warning] 블록 {ack_block}에 대한 중복 ACK 수신. 무시.")

                        pass
                    else:
                        print(f"   [Error] 예상치 못한 ACK 번호 {ack_block} 수신. 현재 {block_number}")

                        error_packet = create_tftp_packet(OPCODE_ERROR, 4, "Illegal TFTP operation")
                        sock.sendto(error_packet, server_address)
                        return

                else:
                    print(f"   [Error] 예상치 못한 Opcode {response_opcode} 수신.")
                    return

    except Exception as e:
        print(f"🚫 업로드 중 예상치 못한 오류 발생: {e}")


def main():
    """
    메인 함수: 명령줄 인수를 처리하고 TFTP 작업을 시작합니다.
    """
    try:

        host, port, operation, filename = parse_args(sys.argv)


        local_port = random.randint(10000, 60000)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.bind(('', local_port))


        server_ip = socket.gethostbyname(host)
        server_address = (server_ip, port)

        print(f"⚙️ TFTP 클라이언트 시작")
        print(f"   서버: {host} ({server_ip}), 포트: {port}")
        print(f"   작업: {operation}, 파일: {filename}")
        print("-" * 30)

        if operation == 'get':
            tftp_get(sock, server_address, filename)
        elif operation == 'put':
            tftp_put(sock, server_address, filename)

    except ValueError as e:
        print(f"❌ 인수 오류: {e}")
        print("   예시:")
        print("   $ python mytftp.py 203.250.133.88 get tftp.conf")
        print("   $ python mytftp.py genie.pcu.ac.kr -p 9988 put tftp.txt")
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