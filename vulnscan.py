import nmap

# Pede ao usuário para inserir a faixa de endereços IP da rede a ser varrida
network = input('Insira a faixa de endereços IP da rede a ser varrida (exemplo: 192.168.1.0/24): ')

# Cria um objeto nmap para varrer a rede em busca de hosts ativos e abertos
nm = nmap.PortScanner()
nm.scan(hosts=network, arguments='-sS -sV -O')

# Varre todos os hosts ativos em busca de vulnerabilidades
for host in nm.all_hosts():
    print('Procurando vulnerabilidades em %s...' % host)
    try:
        # Usa o módulo NSE (Nmap Scripting Engine) do Nmap para procurar vulnerabilidades
        results = nm.scan(hosts=host, arguments='-sS -sV -O --script vuln')

        # Exibe os resultados
        for port in results['scan'][host]['tcp']:
            for vulnerability in results['scan'][host]['tcp'][port]['script']['vuln']:
                print('Vulnerabilidade encontrada na porta %s: %s' % (port, vulnerability))
    except:
        pass
