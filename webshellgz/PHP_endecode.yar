private rule php_endecode
{
    meta:
      date = "2021/09/15"
      author = "nginx"
      rule_type = "Basic"
      version = "1.0"
      confidence = "70"
      create_date = "2021/09/15"
      modify_date = "2021/09/27"
      threat_name = "php-编码操作"
      severity = "medium"
      level = "attack"
      tags = ""
      hash = ""
      reference = "https://github.com/yeyintmg/other-kali-tools/blob/3938c951bc97c9c51a25ea90138fe947b384b674/bin/msf/data/php/reverse_tcp.php"
      description = "包含加解密操作的PHP脚本"

    strings:
      $endefunc1 = /str_replacet[\t ]*\([^)]/ nocase wide ascii
      $endefunc2 = /chr[\t ]*\([^)]/ nocase wide ascii
      $endefunc3 = /base64_decode[\t ]*\([^)]/ nocase wide ascii
      $endefunc4 = /str_rot13[\t ]*\([^)]/ nocase wide ascii
      $endefunc5 = /mb_strtoupper[\t ]*\([^)]/ nocase wide ascii
      $endefunc6 = /strtolower[\t ]*\([^)]/ nocase wide ascii
      $endefunc7 = /strtoupper[\t ]*\([^)]/ nocase wide ascii
      $endefunc8 = /strtr[\t ]*\([^)]/ nocase wide ascii
      $endefunc9 = /substr[\t ]*\([^)]/ nocase wide ascii
      $endefunc10 = /gzcompress[\t ]*\([^)]/ nocase wide ascii
      $endefunc11 = /gzuncompress[\t ]*\([^)]/ nocase wide ascii
      $endefunc12 = /strrev[\t ]*\([^)]/ nocase wide ascii
      $endefunc13 = /str_repeat[\t ]*\([^)]/ nocase wide ascii
      $endefunc14 = /explode[\t ]*\([^)]/ nocase wide ascii
      $endefunc15 = /gzinflate[\t ]*\([^)]/ nocase wide ascii
      $endefunc16 = /preg_replace[\t ]*\([^)]/ nocase wide ascii
      $endefunc17 = /substr_replace[\t ]*\([^)]/ nocase wide ascii
      $endefunc18 = /pack[\t ]*\([^)]/ nocase wide ascii

    condition:
      1 of them
}