private rule ip_address {
    meta:
        date = "2020/12/08"
        author = "nginx"
        rule_type = "Basic"
        version = "1.0"
        confidence = "70"
        create_date = "2020/12/08"
        modify_date = "2020/12/08"
        threat_name = "IP地址"
        severity = "low"
        level = "attack"
        tags = ""
        hash = ""
        reference = ""
        description = "匹配IP地址"
    strings:
        $ip = /((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}/
    condition:
        any of them
}