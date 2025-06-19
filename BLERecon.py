import subprocess
import re
import csv
import json
import os
import sys
import signal
import time
import shutil
import threading
import pyshark
from collections import defaultdict

# Comando para ejecutar el escaneo de ubertooth
cmd = "ubertooth-scan -s -x"

# Diccionario con las características de Features Page 0
FEATURES_PAGE_0 = {
    (0, 0): "3 slot packets",
    (0, 1): "5 slot packets",
    (0, 2): "Encryption",
    (0, 3): "Slot offset",
    (0, 4): "Timing accuracy",
    (0, 5): "Role switch",
    (0, 6): "Hold mode",
    (0, 7): "Sniff mode",
    (1, 1): "Power control requests",
    (1, 2): "Channel quality driven data rate (CQDDR)",
    (1, 3): "SCO link",
    (1, 4): "HV2 packets",
    (1, 5): "HV3 packets",
    (1, 6): "µ-law log synchronous data",
    (1, 7): "A-law log synchronous data",
    (2, 0): "CVSD synchronous data",
    (2, 1): "Paging parameter negotiation",
    (2, 2): "Power control",
    (2, 3): "Transparent synchronous data",
    (2, 4): "Flow control lag (LSB)",
    (2, 5): "Flow control lag (Middle bit)",
    (2, 6): "Flow control lag (MSB)",
    (2, 7): "Broadcast Encryption",
    (3, 1): "Enhanced Data Rate ACL 2 Mb/s",
    (3, 2): "Enhanced Data Rate ACL 3 Mb/s",
    (3, 3): "Enhanced inquiry scan",
    (3, 4): "Interlaced inquiry scan",
    (3, 5): "Interlaced page scan",
    (3, 6): "RSSI with inquiry results",
    (3, 7): "Extended SCO link (EV3 packets)",
    (4, 0): "EV4 packets",
    (4, 1): "EV5 packets",
    (4, 3): "AFH capable slave",
    (4, 4): "AFH classification slave",
    (4, 5): "BR/EDR Not Supported",
    (4, 6): "LE Supported (Controller)",
    (4, 7): "3-slot Enhanced Data Rate ACL packets",
    (5, 0): "5-slot Enhanced Data Rate ACL packets",
    (5, 1): "Sniff subrating",
    (5, 2): "Pause encryption",
    (5, 3): "AFH capable master",
    (5, 4): "AFH classification master",
    (5, 5): "Enhanced Data Rate eSCO 2 Mb/s",
    (5, 6): "Enhanced Data Rate eSCO 3 Mb/s",
    (5, 7): "3-slot Enhanced Data Rate eSCO packets",
    (6, 0): "Extended Inquiry Response",
    (6, 1): "Simultaneous LE and BR/EDR",
    (6, 3): "Secure Simple Pairing",
    (6, 4): "Encapsulated PDU",
    (6, 5): "Erroneous Data Reporting",
    (6, 6): "Non-flushable Packet Boundary Flag",
    (7, 0): "Link Supervision Timeout Changed Event",
    (7, 1): "Inquiry TX Power Level",
    (7, 2): "Enhanced Power Control",
}

# Diccionario con las características de Features Page 1
FEATURES_PAGE_1 = {
    (0, 0): "*Extended Feature* Secure Simple Pairing (Host Support)",
    (0, 1): "*Extended Feature* LE Supported (Host)",
    (0, 2): "*Extended Feature* Simultaneous LE and BR/EDR to Same Device Capable (Host)",
    (0, 3): "*Extended Feature* Secure Connections (Hosts Support)",
}

# Diccionario con las características de Features Page 2
FEATURES_PAGE_2 = {
    (0, 0): "*Extended Feature* Connectionless Slave Broadcast – Master Operation",
    (0, 1): "*Extended Feature* Connectionless Slave Broadcast – Slave Operation",
    (0, 2): "*Extended Feature* Synchronization Train",
    (0, 3): "*Extended Feature* Synchronization Scan",
    (0, 4): "*Extended Feature* HCI_Inquiry_Response_Notification event",
    (0, 5): "*Extended Feature* Generalized interlaced scan",
    (0, 6): "*Extended Feature* Coarse Clock Adjustment",
    (0, 7): "*Extended Feature* Reserved for future use",
    (1, 0): "*Extended Feature* Secure Connections (Controller Support)",
    (1, 1): "*Extended Feature* Ping",
    (1, 2): "*Extended Feature* Reserved for future use - Slot Availability Mask (5.x)",
    (1, 3): "*Extended Feature* Train nudging",
}

# Lista con las caracteristicas de seguridad
SECURITY_FEATURES = {
    "Encryption",
    "Broadcast Encryption",
    "Power control",
    "Secure Simple Pairing",
    "Erroneous Data Reporting",
    "Simultaneous LE and BR/EDR",
    "Enhanced Power Control",
    "*Extended Feature* Secure Simple Pairing (Host Support)",
    "*Extended Feature* Secure Connections (Hosts Support)",
    "*Extended Feature* Secure Connections (Controller Support)",
    "*Extended Feature* Ping"
}

# Función para clasificar el nivel de seguridad
def classify_security_level(features):

    if any("Secure Connections" in f for f in features):
        return "Alto"
    elif any("Secure Simple Pairing" in f for f in features) or "Encryption" in features:
        return "Medio"
    elif "Encryption" in features or "Power control" in features:
        return "Bajo"
    elif not features:
        return "Indeterminado (sin características detectadas)"
    else:
        return "Nulo"

# Función para interpretar Features Page 
FEATURES_DICTS = [FEATURES_PAGE_0, FEATURES_PAGE_1, FEATURES_PAGE_2]

def parse_features(features_hex, page):
    features = []

    clean_hex = "".join(features_hex.replace("0x", "").split())

    try:
        bytes_list = bytes.fromhex(clean_hex)
    except ValueError:
        print(f"⚠️ Advertencia: Características de página {page} no válidas -> '{features_hex}'")
        return features  # Retorna lista vacía en caso de error

    for byte_index, byte_value in enumerate(bytes_list):
        for bit in range(8):
            if byte_value & (1 << bit):  # Si el bit está activo
                    feature_name = FEATURES_DICTS[page].get((byte_index, bit))
                    if feature_name:
                        features.append(feature_name)
    return features

# Función para analizar la salida
def parse_bluetooth_output(output):
    device_pattern = re.compile(r"([0-9A-Fa-f:]{17})\s+([^\n]+)")
    details_pattern = re.compile(r"\s+([A-Za-z0-9\s]+):\s+([^\n]+)")
    features_patterns = [
        re.compile(r"\s+Features page 0:\s+((?:0x[0-9a-fA-F]+\s*)+)"),
        re.compile(r"\s+Features page 1:\s+((?:0x[0-9a-fA-F]+\s*)+)"),
        re.compile(r"\s+Features page 2:\s+((?:0x[0-9a-fA-F]+\s*)+)")
    ]

    devices = {}
    current_device = None

    for line in output.splitlines():
        device_match = device_pattern.match(line)
        if device_match:
            address, name = device_match.groups()
            if not name.strip():
                name = "Desconocido"
            current_device = { "name": name.strip(), "address": address.strip(), "details": {}, "features": [], "security_features": [], "errors": []}
            devices[address] = current_device
        elif current_device:
            detail_match = details_pattern.match(line)
            if detail_match:
                key, value = detail_match.groups()
                current_device["details"][key.strip()] = value.strip()

                for i, pattern in enumerate(features_patterns):
                    match = pattern.match(line)
                    if match:
                        features_hex = match.group(1).replace(" ", "")
                        current_device["features"].extend(parse_features(features_hex, i))
                        current_device["security_features"] = [f for f in current_device["features"] if f in SECURITY_FEATURES]


            elif "failed" in line:
                current_device["errors"].append(line.strip())

    return devices

# Función para guardar en CSV
def save_to_csv(devices, filename):
    # Comprobar si el archivo ya existe
    file_exists = os.path.isfile(filename)

    # Crear un diccionario para los dispositivos existentes (por dirección BD)
    existing_devices = {}

    # Si el archivo ya existe, leerlo y cargar los dispositivos existentes
    if file_exists:
        with open(filename, mode="r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            headers = next(reader, None)  # Leer la cabecera
            for row in reader:
                if len(row) < 11:  # Evitar filas corruptas
                    continue
                existing_devices[row[0]] = row  # Guardar por dirección BD

    # Si el archivo no existe, crear y escribir la cabecera
    if not file_exists:
        with open(filename, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Dirección BD", "Nombre", "LMP Version", "Manufacturer", "Features page 0", "Features page 1", 
                             "Features page 2", "Clock offset", "AFH map", "Características", "Características de Seguridad", "Nivel de seguridad", "Errores"])

    # Abrir el archivo para leer y escribir los datos
    with open(filename, mode="r+", newline="", encoding="utf-8") as file:
        reader = csv.reader(file)
        rows = list(reader)  # Leemos todas las filas del archivo

        # Comienza con las cabeceras (preservadas si el archivo ya existía)
        updated_rows = [rows[0]] if rows else []

        # Recorremos los dispositivos a guardar
        for device in devices.values():
            address = device["address"]

            # Si el dispositivo ya existe, actualiza la fila con los nuevos datos
            if address in existing_devices:
                row = existing_devices[address]
                row[1] = device["name"]
                row[2] = device["details"].get("LMP Version", "N/A")
                row[3] = device["details"].get("Manufacturer", "N/A")
                row[4] = device["details"].get("Features page 0", "N/A")
                row[5] = device["details"].get("Features page 1", "N/A")
                row[6] = device["details"].get("Features page 2", "N/A")
                row[7] = device["details"].get("Clock offset", "N/A")
                row[8] = device["details"].get("AFH Map", "N/A")
                # Unir características con saltos de línea dentro de la misma celda
                row[9] = "\n".join(device["features"])  # Características separadas por salto de línea
                row[10] = "\n".join(device["security_features"]) # Características de seguridad separadas por salto de línea
                level = classify_security_level(device["security_features"])
                row[11] =  level
                row[12] = "; ".join(device["errors"])  # Errores separados por punto y coma

                # Añadir la fila actualizada
                updated_rows.append(row)
            else:
                # Si el dispositivo no existe, agregarlo como una nueva línea
                level = classify_security_level(device["security_features"])
                new_row = [
                    device["address"], 
                    device["name"], 
                    device["details"].get("LMP Version", "N/A"),
                    device["details"].get("Manufacturer", "N/A"), 
                    device["details"].get("Features page 0", "N/A"), 
                    device["details"].get("Features page 1", "N/A"), 
                    device["details"].get("Features page 2", "N/A"), 
                    device["details"].get("Clock offset", "N/A"), 
                    device["details"].get("AFH Map", "N/A"), 
                    "\n".join(device["features"]),  # Características separadas por salto de línea
                    "\n".join(device["security_features"]), # Características de seguridad separadas por salto de línea
                    level,  
                    "; ".join(device["errors"])  # Errores separados por punto y coma
                ]
                updated_rows.append(new_row)  # Añadir como nueva fila

        # Mover al principio del archivo para sobrescribirlo
        file.seek(0)  # Volver al principio del archivo
        file.truncate(0)  # Eliminar el contenido actual

        # Escribir las filas actualizadas
        writer = csv.writer(file)
        writer.writerows(updated_rows)

    print(f"📁 Datos guardados en {filename}")

# Función para guardar en JSON
def save_to_json(devices, filename):
    # Intentar cargar datos previos del JSON si existe
    try:
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as file:
                existing_data = json.load(file)
        else:
            existing_data = {}
    except json.JSONDecodeError:
        print(f"⚠️ Error al leer {filename}. Creando un nuevo archivo.")
        existing_data = {}

    # Actualizar los datos existentes con los nuevos dispositivos
    existing_data.update(devices)

    # Guardar el archivo actualizado
    with open(filename, mode="w", encoding="utf-8") as file:
        json.dump(existing_data, file, indent=4, ensure_ascii=False)

    print(f"📁 Datos actualizados en {filename}")

# Función para comprobar si la interfaz hci utilizada en ubertooth-scan esta operativa
def is_hci_interface_up(interface="hci0"):
    try:
        result = subprocess.check_output(["hciconfig", interface], stderr=subprocess.STDOUT)
        output = result.decode("utf-8")
        return "UP RUNNING" in output
    except subprocess.CalledProcessError:
        return False

# Función para ejecutar el escaneo
def scan_bluetooth_devices(output_format=None, filename=None):
    print("⏳ Escaneando dispositivos Bluetooth...")

    if not is_hci_interface_up():
        print("❌ Error: La interfaz Bluetooth hci0 no está activa. Ejecuta 'sudo hciconfig hci0 up'")
        return

    try:
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        #if process.returncode != 0:
         #   print(f"❌ Error al ejecutar ubertooth-scan(1): {stderr}")
         #   return
    except Exception as e:
        print(f"❌ Error al ejecutar ubertooth-scan(2): {str(e)}")
        return

    devices = parse_bluetooth_output(stdout)

    if devices:
        print(f"✔️ Se han encontrado {len(devices)} dispositivos:")
        # Guardar en el formato especificado
        if output_format == "csv" and filename:
            save_to_csv(devices, filename)
        elif output_format == "json" and filename:
            save_to_json(devices, filename)
        elif output_format == "security":
            for address, device in devices.items():
                print(f"\nDispositivo: {device['name']}")
                print(f"  Dirección BD: {device['address']}")
                for key, value in device["details"].items():
                    if key in ["LMP Version", "Manufacturer", "AFH Map"]:
                        print(f"  {key}: {value}")
                    
                level = classify_security_level(device["security_features"])
                print(f"  🔐 Nivel de seguridad estimado: {level}")

                if device["security_features"]:
                    print("  🔐 Características de seguridad:")
                    for sec_feature in device["security_features"]:
                        print(f"    - {sec_feature}")

                if device["errors"]:
                    for error in device["errors"]:
                        print(f"  🚨 Error: {error}")
        elif output_format == "verbose":
            for address, device in devices.items():
                print(f"\nDispositivo: {device['name']}")
                print(f"  Dirección BD: {device['address']}")
                for key, value in device["details"].items():
                    print(f"  {key}: {value}")

                level = classify_security_level(device["security_features"])
                print(f"  🔐 Nivel de seguridad estimado: {level}")

                if device["security_features"]:
                    print("  🔐 Características de seguridad:")
                    for sec_feature in device["security_features"]:
                        print(f"    - {sec_feature}")
            
                if device["features"]:
                    print("  Características:")
                    for feature in device["features"]:
                        print(f"    <{feature}>")

                if device["errors"]:
                    for error in device["errors"]:
                        print(f"  🚨 Error: {error}")
    else:
        print("❌ No se encontraron dispositivos.")

# Funcion para realizar el sniffing y el tracking de Bluetooth BR
def sniff_and_track_br(lap=None, uadp=None, choice=None, output_format=None):
    lap_set = set()
    uap_map = {}  # Mapeo LAP -> UAP
    lap_regex = re.compile(r"LAP=([0-9a-fA-F]{6})")
    uap_regex = re.compile(r"UAP\s*=\s*0x([0-9a-fA-F]{2})")
    last_lap = None
    output_lines = []

    try:
        if choice=="1":
            print("🚀 Iniciando sniffing de LAP de Bluetooth BR/EDR...")
            with subprocess.Popen(["ubertooth-rx", "-z"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as proc:
                for line in proc.stdout:
                    line = line.strip()
                    print(line)

                    # Buscar y almacenar LAP
                    lap_match = lap_regex.search(line)
                    if lap_match:
                        last_lap = lap_match.group(1).lower()
                        lap_set.add(last_lap)

                    # Buscar y asociar UAP
                    uap_match = uap_regex.search(line)
                    if uap_match and last_lap:
                        uap = uap_match.group(1).lower()
                        uap_map[last_lap] = uap

        elif choice=="2":
            pass 
        elif choice=="3":
            pass
        elif choice=="4":
            pass

    except KeyboardInterrupt:
        print("⛔ Interrumpido por el usuario.")
    except Exception as e:
        print(f"❌ Error durante la captura BLE: {e}")

    # Mostrar y guardar resultados
    if lap_set:
        print("\n✅ Resultado del sniffing:")
        for lap in sorted(lap_set):
            uap = uap_map.get(lap)
            if uap:
                formatted = f"??:??:{uap}:{lap[0:2]}:{lap[2:4]}:{lap[4:6]} --> LAP:{lap}, UAP:{uap}"
            else:
                formatted = f"??:??:??:{lap[0:2]}:{lap[2:4]}:{lap[4:6]} --> LAP:{lap}"
            print(formatted)
            output_lines.append(formatted)

        # Guardar en archivo
        with open("br_results.txt", "w") as f:
            f.write("\n".join(output_lines))
        print("💾 Resultados guardados en 'br_results.txt'.")

    else:
        print("⚠️ No se detectaron LAPs.")

# Funcion para realizar el sniffing y el tracking de Bluetooth LE
def sniff_and_track_ble(mac=None, choice=None, option=None, output_format=None):
    pipe_path = "/tmp/pipe"

    try:
        # Crear FIFO si no existe
        if not os.path.exists(pipe_path):
            print("📎 Creando pipe en /tmp/pipe...")
            os.mkfifo(pipe_path)
        else:
            print("📎 Pipe ya existe, usando /tmp/pipe")

        if choice=="1":
            # Lanzar sniffing Ubertooth-btle y redirigir la salida al pipe
            print("🚀 Iniciando sniffing Bluetooth LE...")
            if output_format == "1":
                ubertooth_proc = subprocess.Popen(
                ["ubertooth-btle", "-n", "-q", pipe_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
                )
            elif output_format == "2":
                ubertooth_proc = subprocess.Popen(
                ["ubertooth-btle", "-n", "-c", pipe_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
                )

        elif choice=="2":
            # Lanzar tracking Ubertooth-btle y redirigir la salida al pipe
            print("🚀 Iniciando tracking Bluetooth LE...")
            if option in ["3","4"]:
                print("🚀 Comenzando el seguimiento del dispotivo: ", mac)
                ubertooth_follow_proc = subprocess.Popen(
                ["ubertooth-btle", "-t", mac],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
                )

                # Asegurarse de que el dispositivo está siendo seguido correctamente
                time.sleep(2)

            if output_format == "1":
                if option in ["2","4"]:
                    ubertooth_proc = subprocess.Popen(
                    ["ubertooth-btle", "-f", "-I", "-c", pipe_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                    )
                else:
                    ubertooth_proc = subprocess.Popen(
                    ["ubertooth-btle", "-f", "-c", pipe_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                    )
            elif output_format == "2":
                if option in ["2","4"]:
                    ubertooth_proc = subprocess.Popen(
                    ["ubertooth-btle", "-f", "-I", "-c", pipe_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                    )
                else:
                    ubertooth_proc = subprocess.Popen(
                    ["ubertooth-btle", "-f", "-c", pipe_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                    )
        
        # Esperar un poco para asegurar que el pipe ya tiene datos
        time.sleep(2)

        # Lanzar Wireshark para leer desde el pipe
        print("📊 Abriendo Wireshark...")
        subprocess.run(["wireshark", "-k", "-i", pipe_path])

        # Al cerrar Wireshark, terminar Ubertooth
        print("🛑 Cerrando captura...")
        ubertooth_proc.terminate()

        if choice=="2" and option=="2":
            print("🛑 Dejando de seguir al dispositivo: ", mac)
            ubertooth_unfollow_proc = subprocess.Popen(
            ["ubertooth-btle", "-tnone"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
            )

    except KeyboardInterrupt:
        print("⛔ Interrumpido por el usuario.")
        ubertooth_proc.terminate()
    except Exception as e:
        print(f"❌ Error durante la captura BLE: {e}")

# Función para ejecutar ubertooth-dump
def run_dump(modality, filename):
    try:
        if modality == "LE":
            return subprocess.Popen(
                ["ubertooth-dump", "-l", "-d", filename],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        elif modality == "BR/EDR":
            return subprocess.Popen(
                ["ubertooth-dump", "-c", "-d", filename],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
    except Exception as e:
        print(f"❌ Error al iniciar la captura: {e}")
        return None

# Función principal para controlar el volcado
def dump_function(modality):
    filename = input("\n📝 Escribe el nombre del archivo donde volcar los bits obtenidos (.bin o .bttb): ")

    process = run_dump(modality, filename)
    if process is None:
        return

    print("\n📡 Capturando bits... Pulsa [Enter] para detener.")
    
    try:
        # Espera a que el usuario pulse Enter
        input()
        process.terminate()
        process.wait()
        print(f"✅ Captura detenida. Bits volcados en '{filename}'")
    except KeyboardInterrupt:
        process.terminate()
        print("\n⛔ Captura interrumpida por el usuario.")
    except Exception as e:
        print(f"❌ Error durante la captura: {e}")

# Diccionario para traducir Company ID conocidos 
COMPANY_IDS = {
    '004c': 'Apple, Inc.',
    '0006': 'Microsoft',
    '000f': 'Broadcom',
    '0075': 'Samsung Electronics',
    '000a': 'Qualcomm Technologies International, Ltd. (QTIL)'
}

# Diccionario para traducir PDU types
PDU_TYPES = {
    '0x00': 'ADV_IND',
    '0x01': 'ADV_DIRECT_IND',
    '0x02': 'ADV_NONCONN_IND',
    '0x03': 'SCAN_REQ',
    '0x04': 'SCAN_RSP',
    '0x05': 'CONNECT_IND',
    '0x06': 'ADV_SCAN_IND',
}



# Función para leer el archivo .pcap (Bluetooth BLE)
def parse_ble_advertisements(pcap_file):
    print(f"\n📂 Mostrando resumen de paquetes del fichero: {pcap_file}\n")

    capture = pyshark.FileCapture(pcap_file, display_filter="btle")

    advertising_summary = defaultdict(lambda: {
        "count": 0,
        "pdu_types": set(),
        "company_id": None,
        "device_name": None
    })

    for packet in capture:
        try:
            if 'BTLE' in packet:
                btle = packet['BTLE']
                adv_address = btle.get_field_value('btle.advertising_address')
                if not adv_address:
                    continue

                # Contar paquetes por dirección
                advertising_summary[adv_address]["count"] += 1

                # Guardar tipo de PDU
                pdu_raw = btle.get_field_value('btle.advertising_header.pdu_type')
                pdu_type = PDU_TYPES.get(pdu_raw, f'Desconocido ({pdu_raw})') if pdu_raw else 'Desconocido'
                advertising_summary[adv_address]["pdu_types"].add(pdu_type)

                # Company ID 
                if hasattr(btle, 'btcommon_eir_ad_entry_company_id') and not advertising_summary[adv_address]["company_id"]:
                    raw_id = btle.get_field_value('btcommon_eir_ad_entry_company_id').lower().replace('0x', '').zfill(4)
                    company_name = COMPANY_IDS.get(raw_id, f'Desconocido (0x{raw_id})')
                    advertising_summary[adv_address]["company_id"] = company_name

                # Device Name
                if hasattr(btle, 'btcommon_eir_ad_entry_device_name') and not advertising_summary[adv_address]["device_name"]:
                    name = btle.get_field_value('btcommon_eir_ad_entry_device_name')
                    advertising_summary[adv_address]["device_name"] = name

        except Exception as e:
            print(f"❌ Error procesando paquete: {e}")

    capture.close()

    # Mostrar resumen
    for address, info in advertising_summary.items():
        print(f"📡 Advertising Address: {address}")
        print(f"🔢 Total Paquetes: {info['count']}")
        print(f"🔹 Tipos de PDU: {', '.join(info['pdu_types'])}")
        if info["company_id"]:
            print(f"🏷️  Company ID: {info['company_id']}")
        if info["device_name"]:
            print(f"📛 Device Name: {info['device_name']}")
        print("-----")

def detect_connect_id(pcap_file):
    print(f"\n🔍 Buscando todos los paquetes CONNECT_IND en: {pcap_file}. Podría tardar unos minutos dependiendo del tamaño del archivo\n")

    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="btle")
        all_packets = list(capture)
        total_packets = []

        for i, packet in enumerate(all_packets):
            try:
                if 'BTLE' in packet:
                    btle = packet['BTLE']
                    pdu_raw = btle.get_field_value('btle.advertising_header.pdu_type')

                    if pdu_raw == '0x05':  # CONNECT_IND
                        init_address = btle.get_field_value('btle.initiator_address')
                        adv_address = btle.get_field_value('btle.advertising_address')
                        number = int(packet.number)

                        print(f"✅ CONNECT_IND detectado")
                        print(f"\t📦 Número real del paquete (Wireshark): {number}")
                        print(f"\t⏱️ Tiempo: {packet.sniff_time}")
                        if not init_address or not adv_address:
                            print("\t⚠️ Paquete con error (Malformed Packet).")
                        else:
                            print(f"\t📡 Dirección del Central (Initiator): {init_address}")
                            print(f"\t📡 Dirección del Periférico (Advertiser): {adv_address}")

                        # Buscar el primer y último paquete de la conexión
                        first_index = None
                        last_index = None

                        for j, pkt in enumerate(all_packets[i+1:], start=i+1):
                            try:
                                if 'BTLE' in pkt:
                                    master = pkt['BTLE'].get_field_value('btle.master_bd_addr')
                                    slave = pkt['BTLE'].get_field_value('btle.slave_bd_addr')

                                    if master == init_address and slave == adv_address:
                                        if first_index is None:
                                            first_index = int(pkt.number)
                                        last_index = int(pkt.number)
                            except AttributeError:
                                continue

                        if first_index and last_index:
                            conexion_status = f"Emparejamiento capturado desde paquete {first_index} hasta {last_index}"
                        else:
                            conexion_status = "❌ No se capturó el emparejamiento"

                        print(f"\t🔍 Estado de la conexión: {conexion_status}")
                        print("-----")

                        total_packets.append({
                            "numero": number,
                            "tiempo": packet.sniff_time,
                            "initiator": init_address,
                            "advertiser": adv_address,
                            "conexion": conexion_status
                        })

            except AttributeError:
                continue

        capture.close()

        if not total_packets:
            print("⚠️ No se encontró ningún paquete CONNECT_IND en la captura.")
        else:
            print(f"🎯 Total CONNECT_IND encontrados: {len(total_packets)}")

        return total_packets

    except Exception as e:
        print(f"❌ Error al analizar el archivo: {e}")
        return None

# Diccionario para traducir Version ID conocidos 
VERSION_IDS = {
    '00': 'Bluetooth Core Specification 1.0b',
    '01': 'Bluetooth Core Specification 1.1',
    '02': 'Bluetooth Core Specification 1.2',
    '03': 'Bluetooth Core Specification 2.0 + EDR',
    '04': 'Bluetooth Core Specification 2.1 + EDR',
    '05': 'Bluetooth Core Specification 3.0 + HS',
    '06': 'Bluetooth Core Specification 4.0',
    '07': 'Bluetooth Core Specification 4.1',
    '08': 'Bluetooth Core Specification 4.2',
    '09': 'Bluetooth Core Specification 5.0',
    '0A': 'Bluetooth Core Specification 5.1',
    '0B': 'Bluetooth Core Specification 5.2',
    '0C': 'Bluetooth Core Specification 5.3',
    '0D': 'Bluetooth Core Specification 5.4',
}

# Diccionario para traducir I/O Capabilities conocidos 
IO_CAPABILITIES = {
    '00': 'DisplayOnly',
    '01': 'DisplayYesNo',
    '02': 'Keyboard Only',
    '03': 'No Input, No Output',
    '04': 'Keyboard, Display',
}

# Diccionario para traducir OOB DATA FLAGS
OOB_DATA = {
    '00': 'OOB Auth. Data Not Present',
    '01': 'OOB Auth. Data Present',
}

# Diccionario para traducir BONDING_FLAGS
BONDING_FLAG = {
    '00': 'No Bonding',
    '01': 'Bonding',
    '02': 'Reserved (Multi-bonding not supported)',
    '03': 'Bonding (Multi-bonding supported)',
}

def parse_key_distribution(hex_value):
    if not hex_value:
        return {
            "encryption_key": False,
            "id_key": False,
            "signature_key": False,
            "link_key": False
        }

    # Convertir a entero y luego a binario con 8 bits (relleno con ceros)
    binary = bin(int(hex_value, 16))[2:].zfill(8)

    # Tomamos solo los últimos 4 bits
    last_4_bits = binary[-4:]

    # Asignamos cada bit a una bandera (según el orden especificado en la especificación BT)
    return {
        "encryption_key": last_4_bits[3] == '1',
        "id_key":         last_4_bits[2] == '1',
        "signature_key":  last_4_bits[1] == '1',
        "link_key":       last_4_bits[0] == '1'
    }

def get_ble_association_method(initiator_io, responder_io, secure_connections):
    """
    Determina el método de asociación BLE basado en las IO capabilities.
    Args:
        initiator_io (int): IO capability del iniciador (0–4)
        responder_io (int): IO capability del respondedor (0–4)
        secure_connections (bool): True si ambos dispositivos soportan Secure Connections
    Returns:
        str: Método de asociación BLE (ej. Just Works, Passkey Entry, etc.)
    """

    io_init = initiator_io
    io_resp = responder_io

    # Tabla basada en la imagen
    matrix = {
        ('00', '00'): "👀 Just Works (Unauthenticated)",
        ('00', '01'): "👀 Just Works (Unauthenticated)",
        ('00', '02'): "🔢 Passkey Entry: Initiator displays, Responder inputs (Authenticated)",
        ('00', '03'): "👀 Just Works (Unauthenticated)",
        ('00', '04'): "🔢 Passkey Entry: Initiator displays, Responder inputs (Authenticated)",

        ('01', '00'): "👀 Just Works (Unauthenticated)",
        ('01', '01'): "👀 Just Works (Unauthenticated)" if not secure_connections else "🔢 Numeric Comparison (Authenticated)",
        ('01', '02'): "🔢 Passkey Entry: Initiator displays, Responder inputs (Authenticated)",
        ('01', '03'): "👀 Just Works (Unauthenticated)",
        ('01', '04'): "🔢 Passkey Entry: Initiator displays, Responder inputs (Authenticated)" if not secure_connections else "🔢 Numeric Comparison (Authenticated)",

        ('02', '00'): "🔢 Passkey Entry: Responder displays, Initiator inputs (Authenticated)",
        ('02', '01'): "🔢 Passkey Entry: Responder displays, Initiator inputs (Authenticated)",
        ('02', '02'): "🔢 Passkey Entry: Both input (Authenticated)",
        ('02', '03'): "👀 Just Works (Unauthenticated)",
        ('02', '04'): "🔢 Passkey Entry: Responder displays, Initiator inputs (Authenticated)",

        ('03', '00'): "👀 Just Works (Unauthenticated)",
        ('03', '01'): "👀 Just Works (Unauthenticated)",
        ('03', '02'): "👀 Just Works (Unauthenticated)",
        ('03', '03'): "👀 Just Works (Unauthenticated)",
        ('03', '04'): "👀 Just Works (Unauthenticated)",

        ('04', '00'): "🔢 Passkey Entry: Responder displays, Initiator inputs (Authenticated)",
        ('04', '01'): "🔢 Passkey Entry: Responder displays, Initiator inputs (Authenticated)" if not secure_connections else "🔢 Numeric Comparison (Authenticated)",
        ('04', '02'): "🔢 Passkey Entry: Responder displays, Initiator inputs (Authenticated)",
        ('04', '03'): "👀 Just Works (Unauthenticated)",
        ('04', '04'): "🔢 Passkey Entry: Initiator displays, Responder inputs (Authenticated)" if not secure_connections else "🔢 Numeric Comparison (Authenticated)",
    }

    return matrix.get((io_init, io_resp), "Unknown")

def summarize_pairing_type(connection):
    """
    Resume el tipo de pairing BLE (Legacy o Secure Connections)
    y el método de emparejamiento (Just Works, Passkey Entry, OOB).
    """

    sc = False
    sc_i_flag = connection.get("sc_i_flag")
    sc_r_flag = connection.get("sc_r_flag")
    oob_i_flag = connection.get("oob_i_flag")
    oob_r_flag = connection.get("oob_r_flag")
    mitm_i_flag = connection.get("mitm_i_flag")
    mitm_r_flag = connection.get("mitm_r_flag")
    ioc_initiator = connection.get("initiator_io_capability")
    ioc_responder = connection.get("responder_io_capability")

    # Tipo de pairing
    if sc_i_flag == 'True' and sc_r_flag == 'True':
        pairing_type = "🔐 LE Secure Connections"
        sc = True
    elif sc_i_flag == 'False' or sc_r_flag == 'False':
        pairing_type = "🔓 LE Legacy Pairing"
    else:
        pairing_type ="❓ No se pudo determinar (Falta el paquete Pairing Request/Response)"

    # Estimación del método de emparejamiento
    if oob_i_flag == 'True' and oob_r_flag == 'True':
        method = "📡 Out Of Band (OOB) (Authenticated)"
    elif ioc_initiator is None or ioc_responder is None:
        method = "❓ No se pudo determinar (IO capabilities faltantes)"

    # Regla simplificada basada en la tabla de la spec
    if mitm_i_flag == 'False' or mitm_r_flag == 'False':
            method = "👀 Just Works (Unauthenticated)"
    else:
        method = get_ble_association_method(ioc_initiator, ioc_responder, sc)
    

    resumen = f"\n🔎 Conclusión de la conexión:\n" \
              f"   - Tipo de Pairing: {pairing_type}\n" \
              f"   - Método: {method}\n"
    return resumen


def analyze_all_connections(pcap_file, total_packets):
    print(f"\n🔎 Analizando todas las conexiones detectadas\n")
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter="btle")
        all_packets = list(capture)

        for conn in total_packets:
            initiator = conn['initiator']
            advertiser = conn['advertiser']
            conn_num = conn['numero']
            conexion_info = conn.get("conexion", "")

            connection = {
                'initiator_address': initiator,
                'responder_address': advertiser,
                'initiator_io_capability': None,
                'responder_io_capability': None,
                'sc_i_flag': None,
                'sc_r_flag': None,
                'mitm_i_flag': None,
                'mitm_r_flag': None,
                'oob_i_flag': None,
                'oob_r_flag': None
            }

            print(f"\n🔗 Analizando conexión (Paquete CONNECT_IND #{conn_num})")
            print(f"🔗 Master: {initiator}")
            print(f"🔗 Slave: {advertiser}")
            print("-----")

            # Verificamos si hay emparejamiento capturado
            emparejamiento = re.search(r"desde paquete (\d+) hasta (\d+)", conexion_info)
            if not emparejamiento:
                print("⚠️ No se capturó el emparejamiento para esta conexión. Se omite el análisis.")
                print("-------------------------")
                continue

            start_pkt = int(emparejamiento.group(1))
            end_pkt = int(emparejamiento.group(2))

            found_both_version = False
            found_pairing_request = False
            found_pairing_response = False
            found_enc_req = False

            for pkt in all_packets:
                try:
                    pkt_num = int(pkt.number)
                    if pkt_num < start_pkt or pkt_num > end_pkt:
                        continue  # fuera del rango de emparejamiento

                    if 'BTLE' in pkt:
                        btle = pkt['BTLE']
                        master_addr = btle.get_field_value('btle.master_bd_addr')
                        slave_addr = btle.get_field_value('btle.slave_bd_addr')

                        
                        if master_addr == initiator and slave_addr == advertiser:

                            # Analisis de los paquetes LL_VERSION_IND
                            opcode = btle.get_field_value('btle.control_opcode')
                            if opcode == '0x0c' and not found_both_version:  # LL_VERSION_IND
                                raw_company_id = btle.get_field_value('btle.control.company_id').lower().replace('0x', '').zfill(4)
                                company_name = COMPANY_IDS.get(raw_company_id, f'Desconocido (0x{raw_company_id})')
                                raw_version_id = btle.get_field_value('btle.control.version_number').lower().replace('0x', '').zfill(2)
                                version = VERSION_IDS.get(raw_version_id, f'Desconocido (0x{raw_version_id})')
                                print(f"✅ LL_VERSION_IND encontrado del master ({initiator}) #{pkt_num}")
                                print(f"\t📅 Timestamp: {pkt.sniff_time}")
                                print(f"\t🏷️ Company ID: {company_name}")
                                print(f"\t📛 Bluetooth Version: {version}")
                                print("-----")

                                # Buscar respuesta LL_VERSION_IND del slave
                                for resp_pkt in all_packets:
                                    try:
                                        resp_num = int(resp_pkt.number)
                                        if resp_num <= pkt_num or resp_num > end_pkt:
                                            continue

                                        if 'BTLE' in resp_pkt:
                                            btle_resp = resp_pkt['BTLE']
                                            master_addr_resp = btle_resp.get_field_value('btle.master_bd_addr')
                                            slave_addr_resp = btle_resp.get_field_value('btle.slave_bd_addr')
                                            opcode_resp = btle_resp.get_field_value('btle.control_opcode')

                                            if (master_addr_resp == initiator and slave_addr_resp == advertiser and opcode_resp == '0x0c'):
                                                raw_company_id = btle_resp.get_field_value('btle.control.company_id').lower().replace('0x', '').zfill(4)
                                                company_name = COMPANY_IDS.get(raw_company_id, f'Desconocido (0x{raw_company_id})')
                                                raw_version_id = btle_resp.get_field_value('btle.control.version_number').lower().replace('0x', '').zfill(2)
                                                version = VERSION_IDS.get(raw_version_id, f'Desconocido (0x{raw_version_id})')
                                                print(f"✅ LL_VERSION_IND encontrado del slave ({advertiser}) #{pkt_num}")
                                                print(f"\t📅 Timestamp: {resp_pkt.sniff_time}")
                                                print(f"\t🏷️ Company ID: {company_name}")
                                                print(f"\t📛 Bluetooth Version: {version}")
                                                print("-----")
                                                found_both_version = True
                                                #break
                                    except AttributeError:
                                        continue
                                #break

                            #Analsis de los paquetes LL_ENC_REQ
                            if opcode == '0x03':
                                found_enc_req = True
                                rand_number = btle.get_field_value('btle.control.random_number')
                                ediv = btle.get_field_value('btle.control.encrypted_diversifier')
                                master_kdiv = btle.get_field_value('btle.control.master_session_key_diversifier')
                                master_iv = btle.get_field_value('btle.control.master_session_initialization_vector')
                                print(f"✅ LL_ENC_REQ encontrado #{pkt_num}")
                                print(f"\t📅 Timestamp: {pkt.sniff_time}")
                                print(f"\t🧩 Encrypted Diversifier (EDIV): {ediv}")
                                print(f"\t🎲 Random Value: {rand_number}")
                                print(f"\t🗝️ Master Session Key Diversifier: {master_kdiv}")
                                print(f"\t🧭 Master Session Initialization Vector: {master_iv}")
                                print("-----")

                            #Analsis de los paquetes LL_ENC_REQ
                            if opcode == '0x04':
                                slave_kdiv = btle.get_field_value('btle.control.slave_session_key_diversifier')
                                slave_iv = btle.get_field_value('btle.control.slave_session_initialization_vector')
                                print(f"✅ LL_ENC_RSP encontrado #{pkt_num}")
                                print(f"\t📅 Timestamp: {pkt.sniff_time}")
                                print(f"\t🗝️ Slave Session Key Diversifier: {slave_kdiv}")
                                print(f"\t🧭 Slave Session Initialization Vector: {slave_iv}")
                                print("-----")
                        
                        
                        if 'BTSMP' in pkt:
                            btsmp = pkt['BTSMP']
                            opcode_btsmp = btsmp.get_field_value('btsmp.opcode')

                            #Analisis de los paquetes Pairing Request/Response
                            if opcode_btsmp in ['0x01','0x02'] and (not found_pairing_request or not found_pairing_response):  # Pairing Request
                                raw_io_capability = btsmp.get_field_value('btsmp.io_capability').lower().replace('0x', '').zfill(2)
                                io_capability = IO_CAPABILITIES.get(raw_io_capability, f'Desconocido (0x{raw_io_capability})')
                                raw_oob_data = btsmp.get_field_value('btsmp.oob_data_flags').lower().replace('0x', '').zfill(2)
                                oob_data = OOB_DATA.get(raw_oob_data, f'Desconocido (0x{raw_oob_data})')
                                ct2_flag = btsmp.get_field_value('btsmp.ct2_flag')
                                keypress_flag = btsmp.get_field_value('btsmp.keypress_flag')
                                secure_connt_flag = btsmp.get_field_value('btsmp.sc_flag')
                                mitm_flag = btsmp.get_field_value('btsmp.mitm_flag')
                                raw_bonding_flag= btsmp.get_field_value('btsmp.bonding_flags').lower().replace('0x', '').zfill(2)
                                bonding_flag = BONDING_FLAG.get(raw_bonding_flag, f'Desconocido (0x{raw_bonding_flag})')
                                if opcode_btsmp == '0x01':
                                    print(f"✅ Pairing request encontrado Master-->Slave #{pkt_num}")
                                    connection['initiator_io_capability'] = raw_io_capability
                                    connection['sc_i_flag'] = secure_connt_flag
                                    connection['mitm_i_flag'] = mitm_flag 
                                    connection['oob_i_flag'] = oob_data 
                                    found_pairing_request = True
                                elif opcode_btsmp == '0x02':
                                    print(f"✅ Pairing response encontrado Slave-->Master #{pkt_num}")
                                    connection['responder_io_capability'] = raw_io_capability
                                    connection['sc_r_flag'] = secure_connt_flag
                                    connection['mitm_r_flag'] = mitm_flag 
                                    connection['oob_r_flag'] = oob_data 
                                    found_pairing_response = True
                                print(f"\t📅 Timestamp: {pkt.sniff_time}")
                                print(f"\t🎛️ IO Capability: {io_capability}")
                                print(f"\t📡 OOB Data Flags: {oob_data}")
                                print(f"\t🛡️ Authentication Request: ")
                                print(f"\t\t-CT2 Flags: {'✅' if ct2_flag == 'True' else '❌'}")
                                print(f"\t\t-Keypress Flag: {'✅' if keypress_flag == 'True' else '❌'}")
                                print(f"\t\t-Secure Connection Flag: {'✅' if secure_connt_flag == 'True' else '❌'}")
                                print(f"\t\t-MitM Flag: {'✅' if mitm_flag == 'True' else '❌'}")
                                print(f"\t\t-Bonding Flag: {bonding_flag}")

                                initiator_key_distribution = btsmp.get_field_value('btsmp.initiator_key_distribution')
                                i_key_flags = parse_key_distribution(initiator_key_distribution)
                                print(f"\t🔐 Claves distribuidas por el initiator:")
                                for key, enabled in i_key_flags.items():
                                    print(f"\t\t - {key}: {'✅' if enabled else '❌'}")
                                responder_key_distribution = btsmp.get_field_value('btsmp.responder_key_distribution')
                                r_key_flags = parse_key_distribution(responder_key_distribution)
                                print(f"\t🔐 Claves distribuidas por el responder:")
                                for key, enabled in r_key_flags.items():
                                    print(f"\t\t - {key}: {'✅' if enabled else '❌'}")
                                print("-----")

                            #Analisis de los paquetes Pairing Confirm
                            if opcode_btsmp == '0x03':
                                confirm_value = btsmp.get_field_value('btsmp.cfm_value')   

                            #Analisis de los paquetes Pairing Random
                            if opcode_btsmp == '0x04':
                                random_value = btsmp.get_field_value('btsmp.random_value') 

                            # Analisis del paquete Encryption Information
                            if opcode_btsmp == '0x06':
                                ltk = btsmp.get_field_value('btsmp.long_term_key')
                                print(f"✅ Long Term Key encontrada: {ltk} #{pkt_num}")
                                print(f"\t📅 Timestamp: {pkt.sniff_time}")
                                print("-----")

                            # Analisis del paquete Master Identification
                            if opcode_btsmp == '0x07':
                                ediv = btsmp.get_field_value('btsmp.ediv')
                                rand_number = btsmp.get_field_value('btsmp.random_value')
                                print(f"✅ Master Identification encontrado #{pkt_num}")
                                print(f"\t📅 Timestamp: {pkt.sniff_time}")
                                print(f"\t🧩 Encrypted Diversifier (EDIV): {ediv}")
                                print(f"\t🎲 Random Value: {rand_number}")
                                print("-----")



                except AttributeError:
                    continue

            if not found_both_version:
                print("⚠️ No se han encontrado ambos LL_VERSION_IND en esta conexión.")
            if not found_pairing_request:
                print("⚠️ No se ha encontrado PAIRING REQUEST en esta conexión.")
            if not found_pairing_response:
                print("⚠️ No se ha encontrado PAIRING RESPONSE en esta conexión.")
            if not found_enc_req:
                print("⚠️ No se han encontrado paquetes con datos sobre la encriptación.")

            resumen = summarize_pairing_type(connection)
            print(resumen)
            print("-------------------------")

        capture.close()

    except Exception as e:
        print(f"❌ Error durante el análisis: {e}")

# Función para enseñar el menu
def print_menu(option):
    print("\n=== Elige un formato de salida ===")
    opt = 0
    if option == 1:
        print("1 - CSV")
        print("2 - JSON")
        print("3 - Pintar por pantalla la salida (solo security features)")
        print("4 - Pintar por pantalla la salida en modo verbose")
        print("0 - ❌ Volver al menu anterior")

        opt = input("\nSelecciona una opción (0-4): ")

    elif option == 2:
        print("1 - DLT_BLUETOOTH_LE_LL_WITH_PHDR")
        print("2 - DLT_PPI + DLT_BLUETOOTH_LE_LL ")
        print("0 - ❌ Volver al menu anterior")

        opt = input("\nSelecciona una opción (0-2): ")
    elif option == 3:
        print("1 - PcapNG")
        print("2 - Pcap")
        print("0 - ❌ Volver al menu anterior")

        opt = input("\nSelecciona una opción (0-2): ")
    return opt

# Función para aplicar las funcionalidades de Bluetooth Low Energy
def br_functionalities():
    while True:
        print("\n=== Menú de opciones Bluetooth BR/EDR (Ubertooth-one)===")
        print("1 - 📡 Sniffing de todos los LAP")
        print("2 - 🧮 Calcular UAP a partir de un LAP dado")
        print("3 - 🧮 Calcular reloj y seguir piconet según un UAP y un LAP dado")
        print("4 - 🎯 Descubrimiento y seguimiento de CLK para un UAP/LAP en particular")
        print("5 - 📡 Detección passiva del canal AFH")
        print("6 - 💾 Iniciar volcado de bits")
        print("7 - 📁 Leer paquetes BLE de un fichero .pcap o .pcapng")
        print("0 - ❌ Volver al menu anterior")

        opcion = input("\nSelecciona una opción (0-7): ")

        if opcion == "1":
            sniff_and_track_br(choice="1")
        elif opcion == "2":
            print("🔨 Función en construcción")
        elif opcion == "3":
            print("🔨 Función en construcción")
        elif opcion == "4":
            print("🔨 Función en construcción")
        elif opcion == "5":
            print("🔨 Función en construcción")
        elif opcion == "6":
            print("🔨 Función en construcción")
        elif opcion == "7":
            print("🔨 Función en construcción")
        elif opcion == "0":
            break
        else:
            print("❌ Opción no válida. Inténtalo de nuevo.")

# Función para aplicar las funcionalidades de Bluetooth Low Energy
def le_functionalities():
    while True:
        print("\n=== Menú de opciones Bluetooth LE (Fases 1/2 - BSAM) ===")
        print("1 - 📡 Sniffing de paquetes de advertisement BLE (Ubertooth-one only)")
        print("2 - 🎯 Seguimiento de un dispositivo y su conexión (Ubertooth-one only)")
        print("3 - 💾 Iniciar volcado de bits (Ubertooth-one only)")
        print("4 - 📁 Leer paquetes BLE de un fichero .pcap o .pcapng")
        print("0 - ❌ Volver al menu anterior")

        opcion = input("\nSelecciona una opción (0-4): ")

        if opcion == "1":
            opt = print_menu(2)

            if opt == "0":
                continue
            elif opt in ["1", "2"]:
                sniff_and_track_ble(choice="1", output_format=opt)
            else:
                print("❌ Opción no válida.")
        elif opcion == "2":
            print("\n=== Elige una opción ===")
            print("1 - Sniffing de paquetes de advertisement BLE hasta conseguir una conexión para seguir")
            print("2 - Sniffing de paquetes de advertisement BLE hasta conseguir una conexión para seguir con interferencia")
            print("3 - Elegir una dirección MAC que seguir")
            print("4 - Elegir una dirección MAC que seguir con interferencia")
            print("0 - ❌ Volver al menu anterior")

            opt_1 = input("\nSelecciona una opción (0-4): ")

            if opt_1 == "0":
                continue
            elif opt_1 in ["1","2"]:
                opt = print_menu(2)

                if opt == "0":
                    continue
                elif opt in ["1", "2"]:
                    sniff_and_track_ble(choice="2", option=opt_1, output_format=opt)
                else:
                    print("❌ Opción no válida.")

            elif opt_1 in ["3","4"]:
                while True:
                    mac = input("\nIntroduce la dirección MAC del dispositivo objetivo (o 0 para volver al menú): ").lower()

                    if mac == "0":
                        break

                    # Validar formato MAC: XX:XX:XX:XX:XX:XX
                    if re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac):
                        print(f"✅ Dirección MAC válida: {mac}")
                        opt = print_menu(2)

                        if opt == "0":
                            continue
                        elif opt in ["1", "2"]:
                            sniff_and_track_ble(mac=mac, choice="2", option= opt_1, output_format=opt)
                        else:
                            print("❌ Opción no válida.")
                
                        break
                    else:
                        print("❌ Formato de dirección MAC no válido. Intenta de nuevo (ej: AA:BB:CC:DD:EE:FF) o vuleve al menu anterior con la opción 0")
            else:
                print("❌ Opción no válida.")

        elif opcion == "3":
            dump_function(modality="LE")

        elif opcion == "4":
            pcap_file = input("\nIntroduce el nombre del archivo a analizar: ")
            if pcap_file.endswith(".pcap") or pcap_file.endswith(".pcapng"):
                parse_ble_advertisements(pcap_file)
            else:
                print("❌ El archivo debe ser .pcap o .pcapng")

        elif opcion == "0":
            break

        else:
            print("❌ Opción no válida. Inténtalo de nuevo.")

# Función para la opción 1
def menu_information():
    while True:
        print("\n=== Menú de opciones de las Fases 1/2 - BSAM ===")
        print("1 - ⚙️ Funciones bluetooth Classic (BR/EDR)")
        print("2 - ⚙️ Funciones Bluetooth Low Energy (LE)")
        print("3 - 🔍 Hacer escaneo extendido de los dispositivos Bluetooth (Ubertooth-one only)")
        print("4 - 📡 Abrir ventana GUI con un analizador de espectro para la banda de 2,4 GHz (Ubertooth-one only)")
        print("0 - ❌ Volver al menu principal")

        opcion = input("\nSelecciona una opción (0-4): ")

        if opcion == "1":
            print("🔨 Función en construcción")
            #br_functionalities()

        elif opcion == "2":
            le_functionalities()

        elif opcion == "3":
            opt = print_menu(1)

            if opt == "0":
                continue
            elif opt == "1":
                formato = "csv"
            elif opt == "2":
                formato = "json"
            elif opt == "3":
                formato = "security"
            elif opt == "4":
                formato = "verbose"
            else:
                print("❌ Opción no válida.")
                continue

            if formato in ["csv", "json"]:
                archivo = input("Nombre del archivo de salida: ")
                if not archivo.endswith(f".{formato}"):
                    print("❌ Formato no válido. Usa 'csv' o 'json'.")
                else:
                    scan_bluetooth_devices(output_format=formato, filename=archivo)
            elif formato in ["security", "verbose"]:
                scan_bluetooth_devices(output_format=formato)
            else:
                print("❌ Formato no válido. Usa 'csv' o 'json'.")

        elif opcion == "4":
            print("🚀 Iniciando el analizador de espectro...")
            ubertooth_proc = subprocess.Popen(
            ["ubertooth-specan-ui"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
            )

        elif opcion == "0":
            break

        else:
            print("❌ Opción no válida. Inténtalo de nuevo.")

# Función para la opción 2
def menu_pairingAuth():
    while True:
        print("\n=== Menú de opciones de las Fases 3/4/5 - BSAM ===")
        print("1 - 📁 Analizar la Autentificación y cifrado de un emparejamiento")
        print("0 - ❌ Volver al menu principal")

        opcion = input("\nSelecciona una opción (0-1): ")

        if opcion == "1":
            pcap_file = input("\nIntroduce el nombre del archivo a analizar (.pcap or .pcapng): ").strip()
            if pcap_file.endswith(".pcap") or pcap_file.endswith(".pcapng"):
                total_packets = detect_connect_id(pcap_file)
                if total_packets:
                    analyze = input("¿Quieres analizar las conexiones? (s/n): ").strip().lower()
                    if analyze == 'n':
                        pass
                    elif analyze == 's':
                        analyze_all_connections(pcap_file, total_packets)
                    else: 
                        print("❌ Entrada inválida.")

                print("Todas las conexiones analizadas.")
                
            else:
                print("❌ El archivo debe ser .pcap o .pcapng")

        elif opcion == "0":
            break

        else:
            print("❌ Opción no válida. Inténtalo de nuevo.")

# Función principal
def main():
    while True:
        print("\n=== Menú de opciones Bluetooth/BSAM===")
        print("1 - Recopilacion de información y descubrimiento de dispositivos (Fases 1 y 2 - BSAM)")
        print("2 - Emparejamiento, Autentificación y Cifrado (Fases 3, 4 y 5 - BSAM)")
        print("0 - ❌ Salir")

        opcion = input("\nSelecciona una opción (0-2): ")

        if opcion == "1":
            menu_information()

        elif opcion == "2":
            menu_pairingAuth()
        

        elif opcion == "0":
            print("👋 Saliendo del programa. ¡Hasta luego!")
            break
        else:
            print("❌ Opción no válida. Inténtalo de nuevo.")


# Ejecutar el escaneo según los argumentos
if __name__ == "__main__":
    main()
