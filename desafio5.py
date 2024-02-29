import socket
from ipaddress import ip_network, ip_address

portas_conhecidas = {
    20: "FTP - Data Transfer",
    21: "FTP - Command Control",
    22: "SSH - Secure Shell",
    23: "Telnet - Unencrypted text communications",
    25: "SMTP - E-mail Routing",
    53: "DNS - Domain Name System",
    67: "DHCP - Server",
    68: "DHCP - Client",
    69: "TFTP - Trivial File Transfer Protocol",
    80: "HTTP - World Wide Web",
    110: "POP3 - E-mail Retrieval",
    111: "RPCbind",
    113: "Ident - Old Server Identification System",
    119: "NNTP - Usenet News Transfer",
    123: "NTP - Network Time Protocol",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP - Internet Message Access Protocol",
    161: "SNMP - Simple Network Management Protocol",
    162: "SNMP Trap",
    179: "BGP - Border Gateway Protocol",
    194: "IRC - Internet Relay Chat",
    220: "IMAP v3",
    389: "LDAP - Lightweight Directory Access Protocol",
    443: "HTTPS - HTTP Secure",
    465: "SMTPS - SMTP over SSL",
    514: "Syslog",
    515: "LPD - Line Printer Daemon",
    530: "RPC",
    543: "Kerberos - Login",
    544: "Kerberos - Remote shell",
    548: "AFP - Apple Filing Protocol",
    554: "RTSP - Real Time Streaming Protocol",
    587: "SMTP - E-mail Submission",
    631: "IPP - Internet Printing Protocol",
    993: "IMAPS - IMAP over SSL",
    995: "POP3S - POP3 over SSL",
    1023: "Reserved"
}

def obter_entrada_usuario():
    alvo = input("Digite o IP, rede ou nome do domínio alvo (exemplo: '192.168.1.1', '192.168.1.0/24' ou 'www.google.com'): ")
    porta_inicial = int(input("Digite o número da porta inicial: "))
    porta_final = int(input("Digite o número da porta final: "))

    if porta_inicial > porta_final:
        print("Erro: A porta inicial deve ser menor ou igual à porta final.")
        exit(1)

    timeout = float(input("Digite o tempo de timeout em segundos (ex: 0.5): "))

    return alvo, (porta_inicial, porta_final), timeout

def resolver_nome_para_ip(alvo):
    try:
        return socket.gethostbyname(alvo)
    except socket.gaierror:
        return None

def escanear_porta(ip, porta, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            resultado = s.connect_ex((ip, porta))
            if resultado == 0:
                return porta
    except socket.error as e:
        print(f"Erro ao escanear porta {porta} no IP {ip}: {e}")
    return None

def escanear_ip(ip, intervalo_portas, timeout):
    print(f"Iniciando escaneamento em {ip}...")
    portas_abertas = []
    for porta in range(intervalo_portas[0], intervalo_portas[1] + 1):
        resultado = escanear_porta(ip, porta, timeout)
        if resultado is not None:
            portas_abertas.append(resultado)
    return ip, portas_abertas

def escanear_portas(alvo, intervalo_portas, timeout):
    try:
        if "/" in alvo or ip_address(alvo):  # Verifica se é um IP ou rede
            rede = ip_network(alvo, strict=False)
            ips_para_escanear = [str(ip) for ip in rede.hosts()]
        else:  # Caso contrário, assume que é um nome de domínio
            ip_resolvido = resolver_nome_para_ip(alvo)
            if ip_resolvido:
                ips_para_escanear = [ip_resolvido]
            else:
                raise ValueError("Não foi possível resolver o nome do domínio.")
    except ValueError:
        print("Entrada inválida.")
        exit(1)

    resultados = {}
    for ip in ips_para_escanear:
        ip, portas_abertas = escanear_ip(ip, intervalo_portas, timeout)
        resultados[ip] = portas_abertas

    return resultados

if __name__ == "__main__":
    alvo, intervalo_portas, timeout = obter_entrada_usuario()
    resultados_escaneamento = escanear_portas(alvo, intervalo_portas, timeout)

    ips_sem_portas = []
    for ip, portas in resultados_escaneamento.items():
        if not portas:
            ips_sem_portas.append(ip)
        else:
            print(f"\nIP: {ip}")
            for porta in portas:
                servico = portas_conhecidas.get(porta, "Serviço desconhecido")
                print(f"Porta {porta}: {servico}")

    if ips_sem_portas:
        print("\nNenhuma porta encontrada para os seguintes IPs:")
        for ip in ips_sem_portas:
            print(ip)
