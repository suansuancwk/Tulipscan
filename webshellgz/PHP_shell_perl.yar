private rule php_shell_by_perl {
    meta:
        date = "2021/10/19"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2021/10/19"
        modify_date = "2021/10/19"
        threat_name = "php-perl反弹shell特征base64"
        severity = "high"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "通过php使用perl反弹shell时的编码特征"
    strings:
        $perl_cmd1 = "cGVybCAtTUlPIC1l"   //perl -MIO -e 
        $perl_cmd2 = "cGVybCAtZQ"   //perl -e

        $perl_socket1 = "PW5ldyBJTzo6U29ja2V0OjpJTkVU"   //=new IO::Socket::INET
        $perl_socket2 = "b2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7"   //;ocket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
        
        $success1 = "cGVybCAtTUlPIC1lICckcD1mb3JrKCk7ZXhpdCxpZiRwOyRjPW5ldyBJTzo6U29ja2V0OjpJTkVU"  
        $success2 = "cGVybCAtZSAndXNlIFNvY2tldDs=" 
    condition:
        ((any of ($perl_cmd*)) and (any of ($perl_socket*))) or
        any of ($success*)
}