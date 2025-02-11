import socket

def send_udp_message(message, ip_address, port):
    # Crea el socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    import socket
import json

def send_udp_json(ip_address, port, test_type, device, token, action, data):
    # Construcción del JSON
    message = {
        "test-type": test_type,
        "data": {
            "device": device,
            "token": token,
            "action": action,
            "data": data
        }
    }

    # Serializar a JSON
    json_message = json.dumps(message)

    # Crear el socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        print(f"Enviando mensaje JSON a {ip_address}:{port}")
        print(json_message)  # Para ver el contenido antes de enviarlo

        # Enviar el mensaje codificado como bytes
        sock.sendto(json_message.encode('utf-8'), (ip_address, port))
        print("Mensaje enviado con éxito.")
    except Exception as e:
        print(f"Error al enviar el mensaje: {e}")
    finally:
        # Cierra el socket
        sock.close()

if __name__ == "__main__":
    # IP y puerto donde está escuchando tu ESP32-C6
    ESP32_IP = "192.168.1.103"  # Reemplaza con la IP de tu ESP32-C6
    ESP32_PORT = 1234  # Reemplaza con el puerto correcto

    # Datos de prueba
    test_type = "Encryption-and-hashing"
    device = "ESP32-C6"
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"  # Token SJWT de ejemplo
    action = "toggle_led"
    data = "on"

    # Enviar mensaje JSON
    send_udp_json(ESP32_IP, ESP32_PORT, test_type, device, token, action, data)
