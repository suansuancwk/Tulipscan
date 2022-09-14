private rule php_statements {
	meta:
		date = "2020/12/08"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2020/12/08"
        modify_date = "2020/12/08"
        threat_name = "php-已公开反弹shell特征"
        severity = "high"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "GitHub等已公开的反弹shell的特征"
	strings:
		 $s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
		 $s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
		 $s3 = "// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck." fullword ascii
		 $s4 = "printit(\"ERROR: Shell process terminated\");" fullword ascii
		 $s5 = "Shell process has been terminated" fullword ascii
		 $s6 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii
         $s7 = "/bin/bash 2>/dev/null <&" fullword ascii

         $c1 = /\/bin\/(sh|bash)[\t ]*/ nocase wide ascii
         $c2 = /\/dev\/(tcp|null)/ nocase wide ascii
	condition:
		(any of ($s*)) or (#c1 == 2 and $c2)
}

private rule php_statement_base64 {
	meta:
		date = "2020/12/08"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2020/12/08"
        modify_date = "2020/12/08"
        threat_name = "敏感base64"
        severity = "medium"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "进行编码后的敏感字段"
	strings:
		 $s1 = "YmFzaCAt" //bash -

         $s2 = "JiAvZGV2L" // & /dev
         $s3 = "ZGV2L3RjcC8" // dev/tcp

	condition:
		$s1 and ($s2 or $s3)
}

private rule php_statement_func {
	meta:
		date = "2020/12/08"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2020/12/08"
        modify_date = "2020/12/08"
        threat_name = "敏感函数"
        severity = "medium"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "敏感函数"
	strings:
		$str1 = /\bnc[\t ]+(((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3})/
        $str2 = /\btelnet[\t ]+(((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3})/
        $str3 = /\bopenssl[\t ]+(s_client|s_server)/
        $str4 = /\bnc[\t ]+\-e[\t ]+/
        $str5 = /\bexec[\t ]?[0-9]*(\<\>)*/
	condition:
		any of ($str*)
}


