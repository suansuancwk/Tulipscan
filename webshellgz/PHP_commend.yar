private rule php_evals {
	meta:
		date = "2021/09/15"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2021/09/15"
        modify_date = "2021/09/22"
        threat_name = "php-命令执行"
        severity = "high"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "包含命令执行函数的php脚本"
	strings:
		// \([^)] to avoid matching on e.g. eval() in comments
		$cpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cpayload10 = /\bpreg_replace[\t ]*\(.{1,100}\/[ismxADSUXju]{0,11}(e|\\x65)/ nocase wide ascii
		$cpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload13 = /\bmb_eregi_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii

		$m_cpayload_preg_filter1 = /\bpreg_filter[\t ]*\([^\)]/ nocase wide ascii
		$m_cpayload_preg_filter2 = "'|.*|e'" nocase wide ascii
		// TODO backticks
	condition:
		any of ( $cpayload* ) or
        all of ( $m_cpayload_preg_filter* )
}

private rule php_execs {
	meta:
		date = "2021/09/15"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2021/09/15"
        modify_date = "2021/09/22"
        threat_name = "php-命令执行"
        severity = "high"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "包含命令执行函数的php脚本"
	strings:
		$xpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$xpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$xpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$xpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$xpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$xpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$xpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
	condition:
		any of ( $xpayload* ) 
}
private rule php_multiple {
	meta:	
		date = "2021/09/15"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2021/09/15"
        modify_date = "2021/09/22"
        threat_name = "php-命令执行"
        severity = "high"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "containing multiple PHP methods for executing OS commands or eval, in plain text"
	strings:
		// \([^)] to avoid matching on e.g. eval() in comments
		$cmpayload1 = /\beval[\t ]*\([^)]/ nocase wide ascii
		$cmpayload2 = /\bexec[\t ]*\([^)]/ nocase wide ascii
		$cmpayload3 = /\bshell_exec[\t ]*\([^)]/ nocase wide ascii
		$cmpayload4 = /\bpassthru[\t ]*\([^)]/ nocase wide ascii
		$cmpayload5 = /\bsystem[\t ]*\([^)]/ nocase wide ascii
		$cmpayload6 = /\bpopen[\t ]*\([^)]/ nocase wide ascii
		$cmpayload7 = /\bproc_open[\t ]*\([^)]/ nocase wide ascii
		$cmpayload8 = /\bpcntl_exec[\t ]*\([^)]/ nocase wide ascii
		$cmpayload9 = /\bassert[\t ]*\([^)0]/ nocase wide ascii
		$cmpayload10 = /\bpreg_replace[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
		$cmpayload11 = /\bpreg_filter[\t ]*\([^\)]{1,100}\/e/ nocase wide ascii
		$cmpayload12 = /\bmb_ereg_replace[\t ]*\([^\)]{1,100}'e'/ nocase wide ascii
		$cmpayload20 = /\bcreate_function[\t ]*\([^)]/ nocase wide ascii
		$cmpayload21 = /\bReflectionFunction[\t ]*\([^)]/ nocase wide ascii
	condition:
		any of ( $cmpayload* )
}

private rule php_commend {
	condition:
		php_evals or php_execs or php_multiple
}

