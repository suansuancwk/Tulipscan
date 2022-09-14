private rule php_bash_string {
    meta:
        date = "2020/12/08"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2020/12/08"
        modify_date = "2020/12/08"
        threat_name = ""
        severity = "medium"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "bash操作的敏感字符串"
    strings:
        $bash1 = /\/bin\/sh[\t ]+/ nocase wide ascii // /bin/sh -
		$bash2 = /\/bin\/bash[\t ]+/ nocase wide ascii // /bin/bash -
        $bash3 = /bash[\t ]+/ nocase wide ascii // /bash -

    condition:
        any of them
}

private rule dev_string {
    meta:
        date = "2020/12/08"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2020/12/08"
        modify_date = "2020/12/08"
        threat_name = ""
        severity = "medium"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "dev设备字符串"
    strings:
        $dev1 = /\/dev\/tcp/ nocase wide ascii // /dev/tcp
        $dev2 = /\/dev\/null/ nocase wide ascii // /dev/null
    condition:
        any of them
}


private rule php_pipe_and_redirect {
    meta:
        date = "2021/09/15"
        author = "nginx"
        rule_type = "Basic"   
        version = "1.0"
        confidence = "70"
        create_date = "2021/09/15"
        modify_date = "2021/09/22"
        threat_name = "重定向、管道拼接"
        severity = "high"
        level = "attack"
        tags = ""
        hash = ""
        reference = "https://github.com/scot1997/dotfiles/blob/80048683fa850c91ec17b3fb901114bbb818c643/Rofi/shells.txt"
        description = "匹配重定向符和管道符"
    strings:
        $guandao1 = /((\/bin\/(ba)?sh)[\t ]*[\|]([\t ]*))/ // /bin/bash | 
        $guandao2 = /[\t ]*[\|]([\t ]*)((\/bin\/(ba)?sh))/ // | /bin/bash
        $guandao3 = /((\/bin\/(ba)?sh)([\t ]*)[\|]([\t ]*)(telnet))/ // /bin/bash | telnet
        $guandao4 = /((\/bin\/(ba)?sh)([\t ]*)[\|]([\t ]*)(nc))/ // /bin/bash | nc
        $guandao5 = /((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}([\t ]*)([0-9]|[1-9]\d{1}|[1-9]\d{2}|[1-9]\d{3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])[\t ]*[\|]([\t ]*)((\/bin\/(ba)?sh))/

        $proc = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
        $proc_openstr1 = "0 => array(\"pipe\", \"r\")"
        $proc_openstr2 = "1 => array(\"pipe\", \"w\")"
        $proc_openstr3 = "2 => array(\""

        $proc_openstr4 = "0 => array('pipe', 'r')"
        $proc_openstr5 = "1 => array('pipe', 'w')"
        $proc_openstr6 = "2 => array('"

        $proc_openstr7 = "array('pipe','r')"
        $proc_openstr8 = "array('pipe','w')"

        $c1 = /[0-9]*(\<|\>)?\&[0-9]?/

    condition:
        (any of ($guandao*)) or 
        ($proc and 2 of ($proc_openstr*)) or
        $c1
}

private rule FIFO_create {
    meta:
        date = "2021/11/04"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2021/11/04"
        modify_date = "2020/11/04"
        threat_name = ""
        severity = "high"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "匹配进行管道创建的函数"
    strings:
        $func1 = /\bmknod[\t ]*([\s\S]*)[\t ]*p/  //匹配 mknod name p
        $func2 = /\bmkfifo[\t ]*(\/([\w\.]+\/?)*)/  //匹配 mkfifo pathname
    condition:
        any of them
}
