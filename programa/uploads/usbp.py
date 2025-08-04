import usb.core
import usb.util

# Buscar todos los dispositivos USB conectados
devices = usb.core.find(find_all=True)

# Iterar sobre cada dispositivo y obtener VID y PID
for device in devices:
    vendor_id = device.idVendor  # Obtener el Vendor ID
    product_id = device.idProduct  # Obtener el Product ID

    # Imprimir el VID y PID en formato hexadecimal
    print(f"Dispositivo encontrado: VID={hex(vendor_id)} PID={hex(product_id)}")