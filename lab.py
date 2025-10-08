#!/usr/bin/python3
import requests
import json
import yaml
import sys

# configuracion del controlador floodlight
CONTROLLER_IP = '10.20.12.94'
CONTROLLER_PORT = '8080'
BASE_URL = f'http://{CONTROLLER_IP}:{CONTROLLER_PORT}'

# ==================== CLASES ====================
class Alumno:
    def __init__(self, nombre, codigo, mac):
        self.nombre = nombre
        self.codigo = codigo
        self.mac = mac
    
    def __str__(self):
        return f"Alumno: {self.nombre}, Código: {self.codigo}, MAC: {self.mac}"
    

    #para el yaml
    def to_dict(self):
        return {
            'nombre': self.nombre,
            'codigo': self.codigo,
            'mac': self.mac
        }


class Servicio:
    def __init__(self, nombre, protocolo, puerto):
        self.nombre = nombre
        self.protocolo = protocolo
        self.puerto = puerto
    
    def __str__(self):
        return f"{self.nombre} ({self.protocolo}:{self.puerto})"
    

     #para el yaml
    def to_dict(self):
        return {
            'nombre': self.nombre,
            'protocolo': self.protocolo,
            'puerto': self.puerto
        }


class Servidor:
    def __init__(self, nombre, ip):
        self.nombre = nombre
        self.ip = ip
        self.servicios = []
    
    def agregar_servicio(self, servicio):
        self.servicios.append(servicio)
    
    def __str__(self):
        servicios_str = ", ".join([str(s) for s in self.servicios])
        return f"Servidor {self.nombre} ({self.ip}) - Servicios: [{servicios_str}]"
    


     #para el yaml
    def to_dict(self):
        return {
            'nombre': self.nombre,
            'ip': self.ip,
            'servicios': [s.to_dict() for s in self.servicios]
        }


class Curso:
    def __init__(self, codigo, nombre, estado):
        self.codigo = codigo
        self.nombre = nombre
        self.estado = estado
        self.alumnos = []
        self.servidores_permitidos = []
    
    def agregar_alumno(self, alumno):
        if alumno not in self.alumnos:
            self.alumnos.append(alumno)
            return True
        return False
    
    def remover_alumno(self, alumno):
        if alumno in self.alumnos:
            self.alumnos.remove(alumno)
            return True
        return False
    
    def agregar_servidor_permitido(self, servidor, servicios_permitidos):
        self.servidores_permitidos.append({
            'servidor': servidor,
            'servicios': servicios_permitidos
        })
    
    def __str__(self):
        return f"Curso {self.codigo}: {self.nombre} ({self.estado})"
    

     #para el yaml
    def to_dict(self):
        return {
            'codigo': self.codigo,
            'nombre': self.nombre,
            'estado': self.estado,
            'alumnos': [a.codigo for a in self.alumnos],
            'servidores': [
                {
                    'nombre': sp['servidor'].nombre,
                    'servicios_permitidos': sp['servicios']
                }
                for sp in self.servidores_permitidos
            ]
        }
#aca termina loq ues se hizo en el ip



class Conexion:

#contador global para dar un id único a cada conexion conn1 conn2 conn3 
#guarda quien se conecta, a donde, que servicio usa, la ruta calculada y los flows instalados.
#asi ya podremos eleiminar flows mas facilmente
    contador = 0
    
    def __init__(self, alumno, servidor, servicio):
        Conexion.contador += 1
        self.handler = f"CONN_{Conexion.contador}"
        self.alumno = alumno
        self.servidor = servidor
        self.servicio = servicio
        self.ruta = None
        self.flow_ids = []
    
    def __str__(self):
        return f"[{self.handler}] {self.alumno.nombre} -> {self.servidor.nombre}:{self.servicio.nombre}"


# ==================== FUNCIONES DE API ====================
#regresando al IP
def get_attachment_points(mac):
    """obtiene el attachment point de un host dado su MAC"""
    url = f'{BASE_URL}/wm/device/'
    headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            devices = response.json()
            
            for device in devices:
                device_mac = device.get('mac', [''])[0] if isinstance(device.get('mac'), list) else device.get('mac', '')
                
                if device_mac.lower() == mac.lower().replace('-', ':'):
                    attachment_points = device.get('attachmentPoint', [])
                    
                    if attachment_points:
                        ap = attachment_points[0]
                        print(ap.get('switchDPID')),
                        print(ap.get('port')),
                        return {
                            'dpid': ap.get('switchDPID'),
                            'port': ap.get('port')
                        }
            
            return None
        else:
            return None
            
    except Exception as e:
        print(f"Error al obtener attachment point: {e}")
        return None

def get_attachment_points_by_ip(ip):
    """Obtiene el attachment point de un host dado su IP"""
    url = f'{BASE_URL}/wm/device/'
    headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            devices = response.json()
            
            for device in devices:
                # Obtener las IPs del device
                device_ips = device.get('ipv4', [])
                
                # Verificar si la IP coincide
                if ip in device_ips:
                    attachment_points = device.get('attachmentPoint', [])
                    
                    if attachment_points:
                        ap = attachment_points[0]
                        print(ap.get('switchDPID')),
                        print(ap.get('port')),
                        return {
                            'dpid': ap.get('switchDPID'),
                            'port': ap.get('port'),
                        }
            
            return None
        else:
            return None
            
    except Exception as e:
        print(f"Error al obtener attachment point por IP: {e}")
        return None

def get_route(src_dpid, src_port, dst_dpid, dst_port):
    """obtiene la ruta entre dos puntos en la red"""
    url = f'{BASE_URL}/wm/topology/route/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json'
    headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    print(url)
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            route_data = response.json()
            
            if route_data:
                route = []
                for hop in route_data:
                    route.append({
                        'switch': hop.get('switch'),
                        'port': hop.get('port')
                    })
                print(route)
                return route
            else:
                return []
        else:
            return []
            
    except Exception as e:
        print(f"Error al obtener ruta: {e}")
        return []


def push_flow(switch_dpid, flow_data):
    """instala un flow entry en un switch"""
    url = f'{BASE_URL}/wm/staticflowpusher/json'
    headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(flow_data))
        return response.status_code == 200
    except Exception as e:
        print(f"Error al instalar flow: {e}")
        return False


def delete_flow(switch_dpid, flow_name):
    """elimina un flow entry de un switch"""
    url = f'{BASE_URL}/wm/staticflowpusher/json'
    headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    
    flow_data = {
        'switch': switch_dpid,
        'name': flow_name
    }
    
    try:
        response = requests.delete(url, headers=headers, data=json.dumps(flow_data))
        return response.status_code == 200
    except Exception as e:
        print(f"Error al eliminar flow: {e}")
        return False


def build_route(conexion, ruta, alumno_ap, servidor_ip):
    """construye e instala los flows necesarios para la conexión"""
    if not ruta:
        print("Error: No hay ruta disponible")
        return False
    
    flow_ids = []
    mac_alumno = conexion.alumno.mac
    mac_servidor = "ff:ff:ff:ff:ff:ff"  # Placeholder, debería obtenerse del servidor
    protocolo = conexion.servicio.protocolo
    puerto = conexion.servicio.puerto
    
    # Flows para ARP (bidireccionales)
    for i, hop in enumerate(ruta):
        # ARP Request (alumno -> servidor)
        flow_name_arp_req = f"{conexion.handler}_ARP_REQ_{i}"
        flow_arp_req = {
            'switch': hop['switch'],
            'name': flow_name_arp_req,
            'priority': '32768',
            'eth_type': '0x0806',
            'idle_timeout': '60',     # Se elimina tras 60s sin tráfico
            'hard_timeout': '300', 
            'active': 'true',
            'actions': f"output={hop['port']}"
        }
        
        if push_flow(hop['switch'], flow_arp_req):
            flow_ids.append({'switch': hop['switch'], 'name': flow_name_arp_req})
        
        # ARP Reply (servidor -> alumno)
        if i > 0:
            prev_hop = ruta[i-1]
            flow_name_arp_rep = f"{conexion.handler}_ARP_REP_{i}"
            flow_arp_rep = {
                'switch': hop['switch'],
                'name': flow_name_arp_rep,
                'priority': '32768',
                'eth_type': '0x0806',
                'idle_timeout': '60',     # Se elimina tras 60s sin tráfico
                'hard_timeout': '300', 
                'active': 'true',
                'actions': f"output={prev_hop['port']}"
            }
            
            if push_flow(hop['switch'], flow_arp_rep):
                flow_ids.append({'switch': hop['switch'], 'name': flow_name_arp_rep})
    
    # Flows para tráfico IP (alumno -> servidor)
    eth_type = '0x0800'  # IPv4
    ip_proto = '6' if protocolo == 'TCP' else '17'  # TCP=6, UDP=17
    
    for i, hop in enumerate(ruta):
        flow_name_fwd = f"{conexion.handler}_FWD_{i}"
        flow_fwd = {
            'switch': hop['switch'],
            'name': flow_name_fwd,
            'priority': '32769',
            'eth_type': eth_type,
            'ipv4_dst': servidor_ip,
            'ip_proto': ip_proto,
            'tcp_dst': str(puerto) if protocolo == 'TCP' else None,
            'udp_dst': str(puerto) if protocolo == 'UDP' else None,
            'active': 'true',
            'actions': f"output={hop['port']}"
        }
        
        # Remover campos None
        flow_fwd = {k: v for k, v in flow_fwd.items() if v is not None}
        
        if push_flow(hop['switch'], flow_fwd):
            flow_ids.append({'switch': hop['switch'], 'name': flow_name_fwd})
    
    # Flows para tráfico de retorno (servidor -> alumno)
    for i in range(len(ruta) - 1, -1, -1):
        hop = ruta[i]
        if i > 0:
            prev_hop = ruta[i-1]
            out_port = prev_hop['port']
        else:
            out_port = alumno_ap['port']
        
        flow_name_rev = f"{conexion.handler}_REV_{i}"
        flow_rev = {
            'switch': hop['switch'],
            'name': flow_name_rev,
            'priority': '32769',
            'eth_type': eth_type,
            'ipv4_src': servidor_ip,
            'ip_proto': ip_proto,
            'tcp_src': str(puerto) if protocolo == 'TCP' else None,
            'udp_src': str(puerto) if protocolo == 'UDP' else None,
            
            'active': 'true',
            'actions': f"output={out_port}"
        }
        
        # Remover campos None
        flow_rev = {k: v for k, v in flow_rev.items() if v is not None}
        
        if push_flow(hop['switch'], flow_rev):
            flow_ids.append({'switch': hop['switch'], 'name': flow_name_rev})
    
    conexion.flow_ids = flow_ids
    print(f"✓ Ruta creada exitosamente: {len(flow_ids)} flows instalados")
    return True


# ==================== SISTEMA DE GESTIÓN ====================
class SistemaGestion:
    def __init__(self):
        self.alumnos = []
        self.cursos = []
        self.servidores = []
        self.conexiones = []
    
    def importar_yaml(self, archivo):
        """Importa datos desde archivo YAML"""
        try:
            with open(archivo, 'r', encoding='utf-8') as file:
                datos = yaml.safe_load(file)
            
            # Cargar alumnos
            if 'alumnos' in datos:
                for a in datos['alumnos']:
                    alumno = Alumno(a['nombre'], a['codigo'], a['mac'])
                    self.alumnos.append(alumno)
            
            # Cargar servidores
            if 'servidores' in datos:
                for s in datos['servidores']:
                    servidor = Servidor(s['nombre'], s['ip'])
                    if 'servicios' in s:
                        for serv in s['servicios']:
                            servicio = Servicio(serv['nombre'], serv['protocolo'], serv['puerto'])
                            servidor.agregar_servicio(servicio)
                    self.servidores.append(servidor)
            
            # Cargar cursos
            if 'cursos' in datos:
                for c in datos['cursos']:
                    curso = Curso(c['codigo'], c['nombre'], c['estado'])
                    
                    # Asociar alumnos
                    if 'alumnos' in c:
                        for codigo_alumno in c['alumnos']:
                            alumno = self.buscar_alumno_por_codigo(codigo_alumno)
                            if alumno:
                                curso.agregar_alumno(alumno)
                    
                    # Asociar servidores permitidos
                    if 'servidores' in c:
                        for srv in c['servidores']:
                            servidor = self.buscar_servidor_por_nombre(srv['nombre'])
                            if servidor:
                                servicios = srv.get('servicios_permitidos', [])
                                curso.agregar_servidor_permitido(servidor, servicios)
                    
                    self.cursos.append(curso)
            
            print(f"✓ Datos importados exitosamente desde {archivo}")
            return True
            
        except Exception as e:
            print(f"Error al importar archivo: {e}")
            return False
    
    def exportar_yaml(self, archivo):
        """Exporta datos a archivo YAML"""
        try:
            datos = {
                'alumnos': [a.to_dict() for a in self.alumnos],
                'cursos': [c.to_dict() for c in self.cursos],
                'servidores': [s.to_dict() for s in self.servidores]
            }
            
            with open(archivo, 'w', encoding='utf-8') as file:
                yaml.dump(datos, file, allow_unicode=True, default_flow_style=False)
            
            print(f"✓ Datos exportados exitosamente a {archivo}")
            return True
            
        except Exception as e:
            print(f"Error al exportar archivo: {e}")
            return False
    
    # Búsqueda
    def buscar_alumno_por_codigo(self, codigo):
        for a in self.alumnos:
            if str(a.codigo) == str(codigo):
                return a
        return None
    
    def buscar_alumno_por_nombre(self, nombre):
        for a in self.alumnos:
            if a.nombre.lower() == nombre.lower():
                return a
        return None
    
    def buscar_curso_por_codigo(self, codigo):
        for c in self.cursos:
            if c.codigo == codigo:
                return c
        return None
    
    def buscar_servidor_por_nombre(self, nombre):
        for s in self.servidores:
            if s.nombre == nombre:
                return s
        return None
    
    def verificar_autorizacion(self, alumno, servidor, servicio):
        """Verifica si un alumno está autorizado para acceder a un servicio"""
        for curso in self.cursos:
            if curso.estado != "DICTANDO":
                continue
            
            if alumno not in curso.alumnos:
                continue
            
            for srv_perm in curso.servidores_permitidos:
                if srv_perm['servidor'] == servidor:
                    if servicio.nombre in srv_perm['servicios']:
                        return True, curso
        
        return False, None
    
    def crear_conexion(self, alumno, servidor, servicio):
        """Crea una conexión entre alumno y servidor"""
        # Verificar autorización
        autorizado, curso = self.verificar_autorizacion(alumno, servidor, servicio)
        
        if not autorizado:
            print(f"✗ Error: Alumno {alumno.nombre} no autorizado para {servicio.nombre} en {servidor.nombre}")
            return None
        
        # Obtener attachment points
        alumno_ap = get_attachment_points(alumno.mac)
        if not alumno_ap:
            print(f"✗ Error: No se encontró attachment point para alumno {alumno.nombre}")
            return None
        
        # Asumimos que el servidor también tiene un attachment point
        # En un caso real, deberíamos obtenerlo dinámicamente
        servidor_ap = get_attachment_points_by_ip(servidor.ip)
        if not servidor_ap:
            print(f"✗ Error: No se encontró attachment point para servidor {servidor.nombre} (IP: {servidor.ip})")
            print(f"   ℹ️  Asegúrate de que H3 haya generado tráfico (ej: ping desde H3)")
            return None
        
        # Obtener ruta
        ruta = get_route(alumno_ap['dpid'], alumno_ap['port'], 
                        servidor_ap['dpid'], servidor_ap['port'])
        
        if not ruta:
            print(f"✗ Error: No se encontró ruta entre {alumno.nombre} y {servidor.nombre}")
            return None
        
        # Crear conexión
        conexion = Conexion(alumno, servidor, servicio)
        conexion.ruta = ruta
        
        # Construir e instalar flows
        if build_route(conexion, ruta, alumno_ap, servidor.ip):
            self.conexiones.append(conexion)
            print(f"✓ Conexión creada: {conexion}")
            return conexion
        else:
            print(f"✗ Error al crear flows para la conexión")
            return None
    
    def eliminar_conexion(self, handler):
        """Elimina una conexión por su handler"""
        for conexion in self.conexiones:
            if conexion.handler == handler:
                # Eliminar flows
                for flow in conexion.flow_ids:
                    delete_flow(flow['switch'], flow['name'])
                
                self.conexiones.remove(conexion)
                print(f"✓ Conexión {handler} eliminada")
                return True
        
        print(f"✗ Conexión {handler} no encontrada")
        return False
    def listar_cursos_con_acceso_servicio(self, nombre_servidor, nombre_servicio):
        """Lista los cursos que tienen acceso a un servicio específico en un servidor"""
        # Buscar el servidor
        servidor = self.buscar_servidor_por_nombre(nombre_servidor)
        if not servidor:
            print(f"✗ Servidor '{nombre_servidor}' no encontrado")
            return []
        
        # Verificar que el servidor tenga el servicio
        servicio_existe = False
        for serv in servidor.servicios:
            if serv.nombre.lower() == nombre_servicio.lower():
                servicio_existe = True
                break
        
        if not servicio_existe:
            print(f"✗ El servidor '{nombre_servidor}' no tiene el servicio '{nombre_servicio}'")
            return []
        
        # Buscar cursos con acceso
        cursos_con_acceso = []
        
        for curso in self.cursos:
            for srv_perm in curso.servidores_permitidos:
                # Verificar si es el servidor correcto
                if srv_perm['servidor'].nombre == nombre_servidor:
                    # Verificar si el servicio está en la lista de permitidos
                    if nombre_servicio.lower() in [s.lower() for s in srv_perm['servicios']]:
                        cursos_con_acceso.append(curso)
                        break
        
        return cursos_con_acceso


# ==================== MENÚS ====================
def menu_principal(sistema):
    while True:
        print("\n" + "="*60)
        print("  SISTEMA DE GESTIÓN SDN - UNIVERSIDAD")
        print("="*60)
        print("1. Importar")
        print("2. Exportar")
        print("3. Cursos")
        print("4. Alumnos")
        print("5. Servidores")
        print("6. Conexiones")
        print("0. Salir")
        print("="*60)
        
        opcion = input("\nSeleccione una opción: ").strip()
        
        if opcion == '1':
            menu_importar(sistema)
        elif opcion == '2':
            menu_exportar(sistema)
        elif opcion == '3':
            menu_cursos(sistema)
        elif opcion == '4':
            menu_alumnos(sistema)
        elif opcion == '5':
            menu_servidores(sistema)
        elif opcion == '6':
            menu_conexiones(sistema)
        elif opcion == '0':
            print("\n¡Hasta luego!")
            break
        else:
            print("Opción no válida")


def menu_importar(sistema):
    archivo = input("\nNombre del archivo YAML: ").strip()
    sistema.importar_yaml(archivo)


def menu_exportar(sistema):
    archivo = input("\nNombre del archivo YAML de salida: ").strip()
    sistema.exportar_yaml(archivo)


def menu_cursos(sistema):
    while True:
        print("\n--- MENÚ CURSOS ---")
        print("1. Listar cursos")
        print("2. Mostrar detalle")
        print("3. Actualizar (agregar/eliminar alumno)")
        print("4. Listar cursos con acceso a un servicio") 
        print("0. Volver")
        
        opcion = input("\nSeleccione una opción: ").strip()
        
        if opcion == '1':
            print("\n=== LISTA DE CURSOS ===")
            for curso in sistema.cursos:
                print(f"- [{curso.codigo}] {curso.nombre} ({curso.estado})")
        
        elif opcion == '2':
            codigo = input("Código del curso: ").strip()
            curso = sistema.buscar_curso_por_codigo(codigo)
            if curso:
                print(f"\n{curso}")
                print(f"Alumnos inscritos: {len(curso.alumnos)}")
                for alumno in curso.alumnos:
                    print(f"  - {alumno}")
            else:
                print("Curso no encontrado")
        
        elif opcion == '3':
            codigo_curso = input("Código del curso: ").strip()
            curso = sistema.buscar_curso_por_codigo(codigo_curso)
            
            if not curso:
                print("Curso no encontrado")
                continue
            
            accion = input("¿Agregar (A) o Eliminar (E) alumno?: ").strip().upper()
            codigo_alumno = input("Código del alumno: ").strip()
            alumno = sistema.buscar_alumno_por_codigo(codigo_alumno)
            
            if not alumno:
                print("Alumno no encontrado")
                continue
            
            if accion == 'A':
                if curso.agregar_alumno(alumno):
                    print(f"✓ Alumno {alumno.nombre} agregado al curso {curso.codigo}")
                else:
                    print("El alumno ya está en el curso")
            elif accion == 'E':
                if curso.remover_alumno(alumno):
                    print(f"✓ Alumno {alumno.nombre} removido del curso {curso.codigo}")
                else:
                    print("El alumno no está en el curso")

        elif opcion == '4':
            nombre_servidor = input("Nombre del servidor: ").strip()
            nombre_servicio = input("Nombre del servicio (ej: ssh, web): ").strip()
            
            cursos = sistema.listar_cursos_con_acceso_servicio(nombre_servidor, nombre_servicio)
            
            if cursos:
                print(f"\n=== CURSOS CON ACCESO A {nombre_servicio.upper()} EN '{nombre_servidor}' ===")
                for curso in cursos:
                    print(f"- [{curso.codigo}] {curso.nombre} ({curso.estado})")
                print(f"\nTotal: {len(cursos)} curso(s)")
            else:
                print(f"\nNo hay cursos con acceso a '{nombre_servicio}' en '{nombre_servidor}'")
        
        elif opcion == '0':
            break            
        
        elif opcion == '0':
            break


def menu_alumnos(sistema):
    while True:
        print("\n--- MENÚ ALUMNOS ---")
        print("1. Listar alumnos")
        print("2. Mostrar detalle")
        print("3. Crear alumno")
        print("0. Volver")
        
        opcion = input("\nSeleccione una opción: ").strip()
        
        if opcion == '1':
            filtro = input("Filtrar por curso (código) o Enter para todos: ").strip()
            print("\n=== LISTA DE ALUMNOS ===")
            
            if filtro:
                curso = sistema.buscar_curso_por_codigo(filtro)
                if curso:
                    for alumno in curso.alumnos:
                        print(f"- {alumno}")
                else:
                    print("Curso no encontrado")
            else:
                for alumno in sistema.alumnos:
                    print(f"- {alumno}")
        
        elif opcion == '2':
            codigo = input("Código del alumno: ").strip()
            alumno = sistema.buscar_alumno_por_codigo(codigo)
            if alumno:
                print(f"\n{alumno}")
            else:
                print("Alumno no encontrado")
        
        elif opcion == '3':
            nombre = input("Nombre: ").strip()
            codigo = input("Código: ").strip()
            mac = input("MAC: ").strip()
            
            alumno = Alumno(nombre, codigo, mac)
            sistema.alumnos.append(alumno)
            print(f"✓ Alumno {nombre} creado exitosamente")
        
        elif opcion == '0':
            break


def menu_servidores(sistema):
    while True:
        print("\n--- MENÚ SERVIDORES ---")
        print("1. Listar servidores")
        print("2. Mostrar detalle")
        print("0. Volver")
        
        opcion = input("\nSeleccione una opción: ").strip()
        
        if opcion == '1':
            print("\n=== LISTA DE SERVIDORES ===")
            for servidor in sistema.servidores:
                print(f"- {servidor.nombre} ({servidor.ip})")
        
        elif opcion == '2':
            nombre = input("Nombre del servidor: ").strip()
            servidor = sistema.buscar_servidor_por_nombre(nombre)
            if servidor:
                print(f"\n{servidor}")
            else:
                print("Servidor no encontrado")
        
        elif opcion == '0':
            break


def menu_conexiones(sistema):
    while True:
        print("\n--- MENÚ CONEXIONES ---")
        print("1. Crear conexión")
        print("2. Listar conexiones")
        print("3. Borrar conexión")
        print("0. Volver")
        
        opcion = input("\nSeleccione una opción: ").strip()
        
        if opcion == '1':
            codigo_alumno = input("Código del alumno: ").strip()
            alumno = sistema.buscar_alumno_por_codigo(codigo_alumno)
            
            if not alumno:
                print("Alumno no encontrado")
                continue
            
            nombre_servidor = input("Nombre del servidor: ").strip()
            servidor = sistema.buscar_servidor_por_nombre(nombre_servidor)
            
            if not servidor:
                print("Servidor no encontrado")
                continue
            
            print(f"\nServicios disponibles en {servidor.nombre}:")
            for i, serv in enumerate(servidor.servicios):
                print(f"{i+1}. {serv}")
            
            idx = int(input("Seleccione servicio: ").strip()) - 1
            if 0 <= idx < len(servidor.servicios):
                servicio = servidor.servicios[idx]
                sistema.crear_conexion(alumno, servidor, servicio)
            else:
                print("Servicio no válido")
        
        elif opcion == '2':
            print("\n=== CONEXIONES ACTIVAS ===")
            for conexion in sistema.conexiones:
                print(f"- {conexion}")
        
        elif opcion == '3':
            handler = input("Handler de la conexión: ").strip()
            sistema.eliminar_conexion(handler)
        
        elif opcion == '0':
            break


def main():
    print("=== LABORATORIO 4 - Aplicación SDN ===\n")
    sistema = SistemaGestion()
    menu_principal(sistema)


if __name__ == "__main__":
    main()