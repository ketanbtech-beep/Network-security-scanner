import socket


def grab_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        sock.connect((target, port))

        request = (
            "HEAD / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.send(request.encode())

        response = sock.recv(1024).decode(errors="ignore")

        sock.close()

        if response:
            return response.split("\r\n")[0]

        return "No banner information available"

    except Exception:
        return "No banner information available"
