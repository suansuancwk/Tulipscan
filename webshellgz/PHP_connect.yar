private rule php_socket_connect {
    meta:
        date = "2021/09/15"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2021/09/15"
        modify_date = "2021/09/22"
        threat_name = "php-socker连接"
        severity = "medium"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "包含网络通信的php脚本"
    strings:
        $socket1 = "socket_addrinfo_bind"
        $socket2 = "socket_addrinfo_connect"
        $socket3 = "socket_read"
        $socket4 = "socket_send"
        $socket5 = "socket_write"
        $socket6 = "socket_recv"
        $socket7 = "socket_create"
        $socket8 = "socket_connect"
        $socket9 = "socket_close"
        $socket10 = "socket_accept"

        $bind1 = "socket_bind"
        $bind2 = "socket_create"
        $bind3 = "socket_listen"

        $crl = "socket_create_listen"
        
        $socketopen = /\bfsockopen[\t ]*\([^)]/ nocase wide ascii
        $socketopen1 = /\bpfsockopen[\t ]*\([^)]/ nocase wide ascii
    condition:
         2 of ($socket*) or 2 of ($bind*) or $crl or 1 of ($socketopen*)
}

private rule php_stram_connect {
    meta:
        date = "2021/09/15"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2021/09/15"
        modify_date = "2021/09/22"
        threat_name = "php-socker连接"
        severity = "medium"
        level = "attack"
        tags = ""
        hash = ""
        reference = "https://github.com/yeyintmg/other-kali-tools/blob/3938c951bc97c9c51a25ea90138fe947b384b674/bin/msf/data/php/reverse_tcp.php"
        description = "包含网络通信stream函数的php脚本"
    strings:
        $stram1 = "stream_socket_client"
        $stram2 = "stream_socket_accept"
        $stram3 = "stream_socket_server"
    condition:
        1 of them //一般为stream_socket_accept搭配server或client
}

private rule php_UDP {
    meta:
        date = "2021/09/15"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2021/09/15"
        modify_date = "2021/09/22"
        threat_name = "php-udp连接"
        severity = "medium"
        level = "attack"
        tags = ""
        hash = ""
        reference = "https://github.com/andyowenx/wargame_write-up/blob/31a717ee028457fad3f7d3fc7ca65beb1c0b4a18/vulnhub/prime_1/metasploit_reverse_shell.php"
        description = "包含udp通信的php脚本"
    strings:
        $udp = "udp://"
    condition:
        any of them
}

private rule php_TCP {
    meta:
        date = "2021/09/15"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2021/09/15"
        modify_date = "2021/09/22"
        threat_name = "php-tcp连接"
        severity = "medium"
        level = "attack"
        tags = ""
        hash = ""
        reference = "https://github.com/for-just-we/webshell_sample/blob/051903ec3e9585ea80dc5e68799fe1433502d842/train/webshell/mark668.php"
        description = "包含tcp通信的php脚本"
    strings:
        $tcp = "tcp://"
    condition:
        any of them
}