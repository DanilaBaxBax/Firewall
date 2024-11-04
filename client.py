import socket

def test_firewall(ip, port=9999):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            data = s.recv(1024)
            print('Получено:', data.decode('utf-8'))
    except Exception as e:
        print(f"Ошибка при подключении к файрволу: {e}")

if __name__ == "__main__":
    test_firewall('localhost')
