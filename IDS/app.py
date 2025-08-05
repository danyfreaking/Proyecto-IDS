from flask import Flask, render_template, request, jsonify # Importar Flask y funciones necesarias para renderizar plantillas HTML y manejar solicitudes
import time # modulo de tiempo para el monitoreo y deteccion 
import scapy.all as scapy # libreria para la manipulación y análisis de paquetes de red
import threading #ejecutar funciones en segundo plano (por ejemplo, monitoreo de red)
import subprocess #ejecutar comandos del sistema y manipular procesos externos

app = Flask(__name__) #Se crea la instancia de Flask 

# Diccionarios para almacenar las alertas
alerted_ports = {}
alerted_pings = {}

# Variables para almacenar las alertas
alerts = {
    "network_alerts": [],
    "port_scan_alerts": []
}

# ========================== FUNCIONES DE DETECCIÓN ========================== #
# Función para detectar un escaneo de puertos
def detect_port_scan(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP): # Verificar si el paquete tiene capa IP y capa TCP
        src_ip = packet[scapy.IP].src # Obtener la dirección IP de origen del paquete
        dst_ip = packet[scapy.IP].dst # Obtener la dirección IP de destino
        src_port = packet[scapy.TCP].sport # Obtener el puerto de origen del paquete TCP
        dst_port = packet[scapy.TCP].dport # Obtener el puerto de destino del paquete TCP

# Verificar si el paquete tiene el flag SYN activado (esto indica un intento de escaneo de puertos)
        if packet[scapy.TCP].flags == "S": 
            pair = (src_ip, dst_ip, src_port, dst_port)  # Emparejar la información de IP y puertos de origen y destino
            current_time = time.time()

            if dst_ip not in alerted_ports or (current_time - alerted_ports[dst_ip]) > 15:
                alert_message = {
                    "icon": "<i class='fas fa-exclamation-triangle'></i>",  # Icono para la alerta
                    "title": "Posible escaneo de puertos detectado",
                    "src_ip": src_ip,  # La IP de origen
                    "src_port": src_port,  # El puerto de origen
                    "dst_ip": dst_ip,  # La IP de destino
                    "dst_port": dst_port,  # El puerto de destino
                }
                alerts["network_alerts"].append(alert_message)  # Agregar la alerta al diccionario
                alerted_ports[dst_ip] = current_time
                print(f"Alerta de escaneo de puertos agregada: {alert_message}")
                

# Función para detectar pings ICMP
def detect_ping(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.ICMP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst   
        current_time = time.time()

        pair = (src_ip, dst_ip)
        if pair not in alerted_pings or (current_time - alerted_pings[pair]) > 7:  # Pings sospechosos cada 7s
            alert_message = {
            "icon": "<i class='fas fa-bell'></i>",  # Icono para la alerta de ping
            "title": "Posible ataque de Ping detectado",
            "src_ip": src_ip,  # La IP de origen
            "dst_ip": dst_ip,  # La IP de destino
            "src_port": None,  # Sin puerto para los pings
            "dst_port": None,  # Sin puerto para los pings
            }      
            alerts["network_alerts"].append(alert_message)  # Agregar la alerta al diccionario
            alerted_pings[pair] = current_time
            print(f"Alerta de Ping agregada: {alert_message}")


# ========================== FUNCIONES DE MONITOREO ========================== #

# Monitorear tráfico de red en una interfaz específica
def sniff_traffic_iface(iface):
    print(f"\n[🔍] Monitoreando tráfico de red en la interfaz {iface}...\n")
    scapy.sniff(filter="", prn=process_packet, store=False, iface=iface, timeout=10)  # Filtrado sin restricciones, captura todo

# Procesar cada paquete y pasarlo a la detección
def process_packet(packet):
    detect_port_scan(packet)  # Detectar escaneo de puertos
    detect_ping(packet)       # Detectar pings ICMP

# Función para monitorear tráfico de red automáticamente en ambas interfaces
def start_network_monitoring():
    # Iniciar monitoreo en dos hilos separados (Ethernet y Wi-Fi)
    ethernet_thread = threading.Thread(target=sniff_traffic_iface, args=("Ethernet",))
    ethernet_thread.start()

    wifi_thread = threading.Thread(target=sniff_traffic_iface, args=("Wi-Fi",))
    wifi_thread.start()

    # Espera 10 segundos mientras se monitorean ambas interfaces
    time.sleep(10)  
    ethernet_thread.join()
    wifi_thread.join()


# Ruta principal que renderiza la página de inicio.
@app.route('/')
def index():
    return render_template('index.html')

# Ruta para la página de monitoreo de red.
@app.route('/network_monitoring')
def network_monitoring():
    # Iniciar monitoreo en segundo plano
    threading.Thread(target=start_network_monitoring).start()
    return render_template('network_monitoring.html', alerts=alerts["network_alerts"])

# Ruta para escanear puertos.
# Recibe la IP de destino y ejecuta el escaneo de puertos.
@app.route('/port_scan', methods=['POST', 'GET'])
def port_scan():
    if request.method == 'POST':
        target_ip = request.form['target_ip']
        scan_ports(target_ip)  # Llamada a la función sin el intervalo
    return render_template('port_scan.html', alerts=alerts["port_scan_alerts"])


# Devuelve las alertas de red y escaneo de puertos
@app.route('/get_alerts', methods=['GET'])
def get_alerts():
    # Devolver las alertas actuales en formato JSON
    return jsonify({
        "network_alerts": alerts["network_alerts"],
        "port_scan_alerts": alerts["port_scan_alerts"]
    })

# Ruta para limpiar las alertas.
@app.route('/clear_alerts', methods=['POST'])
def clear_alerts():
    # Limpiar las alertas cuando el usuario regresa al menú
    alerts["port_scan_alerts"] = []
    alerts["network_alerts"] = []

    # Asegurarse de que la respuesta se maneje bien
    return jsonify({'status': 'success'}), 200



# ========================== FUNCIONES PARA ESCANEO DE PUERTOS ========================== #
# Función para escanear puertos sin intervalo
def scan_ports(target_ip, max_attempts=5):
    attempts = 0
    alerts["port_scan_alerts"].append(f"Escaneando la IP: {target_ip}...")

    while attempts < max_attempts:
        try:
            result = subprocess.run(["nmap", "-p", "1-1024", target_ip], capture_output=True, text=True)
            if "open" in result.stdout:
                # Procesar las líneas que contienen "open" y agregar el HTML para los iconos
                port_alerts = [f"<i class='fas fa-lock-open'></i> {line}" for line in result.stdout.split("\n") if "open" in line]
                alerts["port_scan_alerts"].extend(port_alerts)
                # Agregar un mensaje indicando que se detectaron puertos abiertos
                alerts["port_scan_alerts"].append(f"<i class='fas fa-network-wired custom-icon'></i> Puertos abiertos detectados en la IP {target_ip}.")
            else:
                alerts["port_scan_alerts"].append(f"<i class='fas fa-network-wired open-port'></i> No se detectaron puertos abiertos en la IP {target_ip}.")
            break  # Si el escaneo se completa, termina el ciclo
        except FileNotFoundError:
            alerts["port_scan_alerts"].append("[ERROR] Nmap no está instalado.")
            break
        attempts += 1


# ========================== FUNCIONES PARA DETECCIÓN DE USB ========================== #
# Importación de librerías para interactuar con COM (Component Object Model) en Windows:

import win32com.client #permite acceder y controlar objetos COM (como aplicaciones de Microsoft Office),
import pythoncom  # proporciona soporte para la interfaz COM en Python, usado junto con 'win32com'.


# Lista de dispositivos autorizados (nombre del dispositivo)
known_usb_devices = [
   "KingstonDataTraveler_2.01",
    "USBSTOR\\DiskKingstonDataTraveler_2.01.00",
    "USBSTOR\\DiskKingstonDataTraveler_2.0",
    "USBSTOR\\KingstonDataTraveler_2.01",
    "USB\\VID_0951&PID_1665\\60A44C426518F0A0363335C1",
   "USB\\VID_04F2&PID_B1D6\\6&2C9DDD91&0&4",
   "USB\\VID_8087&PID_0024\\5&31C9D4A9&0&1",
   "USB\\VID_1EA7&PID_0066\\6&2C9DDD91&0&1"
   "USB\\ROOT_HUB20\\4&125BC64D&0",
   "USB\\ROOT_HUB20\\4&17684393&0",
   "USB\\VID_0BDA&PID_0138\\20090516388200000",
   "USB\\VID_1EA7&PID_0066\\6&2C9DDD91&0&1"
]

# Función para detectar dispositivos USB y clasificarlos
def detect_usb_devices():
    pythoncom.CoInitialize()  # Inicializa COM antes de usar win32com
    wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    service = wmi.ConnectServer(".", "root\\cimv2")
    
    # Consultar los dispositivos USB conectados
    devices = service.ExecQuery("SELECT * FROM Win32_USBHub")
    
    authorized_devices = []
    malicious_devices = []
    
    for device in devices:
        device_id = device.DeviceID
        description = device.Description
        is_known = any(known_device in device_id for known_device in known_usb_devices)
        status = "Autorizado" if is_known else "Malicioso"
        
        device_info = {
            'device_id': device_id,
            'description': description,
            'status': status
        }
        
        if status == "Autorizado":
            authorized_devices.append(device_info)
        else:
            malicious_devices.append(device_info)
    
    return authorized_devices, malicious_devices

# Ruta para mostrar alertas de dispositivos USB.
@app.route('/usb_alerts')
def usb_page():  
# Detecta los dispositivos USB conectados y los clasifica en autorizados y maliciosos.
    authorized_devices, malicious_devices = detect_usb_devices()
    return render_template('usb_alerts.html', 
                           authorized_devices=authorized_devices, 
                           malicious_devices=malicious_devices)


# ========================== FUNCIONES PARA ANÁLISIS DE ARCHIVOS ========================== #
# Importación de librerías necesarias para el análisis de archivos:
import os # para operaciones con el sistema de archivos,
import hashlib #  calcular hashes de archivos,
import struct # manipulación de datos binarios,
import requests #  para realizar peticiones HTTP (usado con la API de VirusTotal),
from PyPDF2 import PdfReader  # para leer y analizar archivos PDF.


# Configuración de la carpeta de subida de archivos
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# API de VirusTotal (usando una clave de API)
VIRUS_TOTAL_API_KEY = "d11f9324679c4f2206a6cabb8a0b62f40b23fd50caf71aaf8b896aab1caecd37"
VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/files/"


# Función para verificar si el archivo es un PDF y está corrupto
def is_pdf_corrupt(file_path):
    try:
        reader = PdfReader(file_path)
        reader.pages  # Si no lanza excepción, es un archivo válido
        return False
    except Exception as e:
        return True  # Si hay un error, es un archivo corrupto

# Función para verificar si el archivo tiene un tipo sospechoso (ejecutables o scripts)
def is_suspicious(file_path):
    file_extension = os.path.splitext(file_path)[1].lower()
    # Archivos ejecutables (.exe, .dll, .bat, .msi)
    if file_extension in ['.exe', '.dll', '.bat', '.msi']:
        return True
    # Archivos de script (.vbs, .js, .py)
    if file_extension in ['.vbs', '.js', '.py']:
        return True
    return False

# Función para verificar si un archivo Python tiene código peligroso
def is_suspicious_python(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            # Buscar patrones peligrosos como os.system, subprocess, eval, etc.
            dangerous_patterns = ['os.system', 'subprocess', 'eval', 'exec']
            for pattern in dangerous_patterns:
                if pattern in content:
                    return True  # Si encontramos algo peligroso
    except Exception as e:
        return True  # Si hay un error al leer el archivo
    return False

# Función para verificar si el archivo tiene malware usando VirusTotal
def check_malware_with_virustotal(file_path):
    headers = {
        "x-apikey": VIRUS_TOTAL_API_KEY
    }

    # Calcular el hash del archivo
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    # Realizar la consulta a VirusTotal con el hash
    response = requests.get(VIRUS_TOTAL_URL + file_hash, headers=headers)

    if response.status_code == 200:
        json_response = response.json()
        data = json_response.get('data', {}).get('attributes', {})
        if 'last_analysis_stats' in data:
            malicious_count = data['last_analysis_stats'].get('malicious', 0)
            if malicious_count > 0:
                return True  # Archivo malicioso
    return False  # No malicioso

# Función principal para analizar el archivo
def analyze_file(file_path):
    # Primero, verificar si el archivo es sospechoso basado en su tipo
    if is_suspicious(file_path):
        return "Archivo sospechoso: Ejecutable o Script detectado."

    # Verificar si el archivo es un PDF y está corrupto
    if file_path.endswith('.pdf') and is_pdf_corrupt(file_path):
        return "Archivo PDF corrupto."

    # Verificar si es un archivo Python y tiene patrones peligrosos
    if file_path.endswith('.py') and is_suspicious_python(file_path):
        return "Archivo Python sospechoso, contiene código peligroso."

    # Verificar si el archivo tiene malware con VirusTotal
    if check_malware_with_virustotal(file_path):
        return "Archivo malicioso detectado por VirusTotal."

    return "Archivo seguro."

# Ruta para el análisis de archivos
@app.route('/file_analysis', methods=['GET', 'POST'])
def file_analysis():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            # Guardar archivo temporalmente en el directorio uploads
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)

            # Realizar el análisis de seguridad
            file_status = analyze_file(file_path)

            # Mostrar resultado en la página
            return render_template('file_analysis.html', 
                                   file_name=file.filename, 
                                   file_status=file_status)

    return render_template('file_analysis.html', file_name=None)


#Ejecuta la aplicación Flask en modo depuración en la IP local (127.0.0.1) y puerto 5000 
if __name__ == "__main__":
    app.run(debug=True)    



