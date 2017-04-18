<?php
class webSocket{
    private $address    = '127.0.0.6';
    private $port       = '8080';
    private $limit      = 10;
    private $mcrypt_key = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';	//websocket协议中用于加密的字符串
    private $socket;
    private $readfds  = [];
    private $writefds = [];
    private $except   = [];
    private $names    = [];
    public function __construct(){
        $this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP) or die('socket创建失败');
        socket_bind($this->socket, $this->address, $this->port) or die('bind failed');
        socket_listen($this->socket, $this->limit) or die('listen failed');
        $this->readfds[] = $this->socket;
    }
    public function run(){
        while(true){
            $socketArray = $this->readfds;
            socket_select($socketArray, $this->writefds, $this->except, 3600);
            foreach($socketArray as $sock){
                // 监听端口活跃
                if( $this->socket == $sock ){
                    $client = socket_accept( $this->socket );
                    $this->addClient($client);
                }else{
                    $data = socket_read($sock, 1024);
                    if( $data == ""){
                        unset($this->readfds[ $this->getKey($sock) ]);
                        continue;
					}else if(preg_match('/Sec-WebSocket-Key: (.*)\r\n/', $data, $websocketKey)){
						$upgrade = $this->createHandShake( $websocketKey[1] );
						socket_write($sock, $upgrade, strlen($upgrade));
                        $this->sendWellcome($sock);
					}else{
                        $data = $this->decode($data);
                        if( preg_match('|name-setting-(.*)|', $data, $name )){
                            $this->names[ $this->getKey($sock) ] = $name[1];
                            $this->console($name[1]." join");
                            // 通知其他人新朋友加入
                            $data = "Server : ".$name[1]." Join The Talk!";
                            $this->sendToOtherClient($data, $sock);
                        }else{
                            $this->console($this->names[$this->getKey($sock)].' : '.$data);
                            $this->sendToAllClient($data, $sock);
                        }
					}
                }
            }
        }
    }

    /**
     * 升级websocket协议
     * @param $client_key 客户端送来的key
     * @return string     返回给客户端的通知
     */
    private function createHandShake($client_key){
		$key = base64_encode( sha1($client_key.$this->mcrypt_key, true) );
		$upgrade  = "HTTP/1.1 101 Switching Protocol\r\n" .
					"Upgrade: websocket\r\n" .
					"Connection: Upgrade\r\n" .
					"Sec-WebSocket-Accept: " . $key . "\r\n\r\n";		//结尾一定要两个\r\n\r\n
		return $upgrade;
	}

    /**
     * 添加客户端套接字到数组
     * @param $client
     */
    private function addClient( $client){
        $this->readfds[] = $client;
    }

    /**
     * 发送欢迎消息
     * @param $sock
     */
    private function sendWellcome($sock){
        $string = $this->encode('Server : Well Join The Talk!');
        socket_write($sock, $string);
    }

    /**
     * 发送消息到所有客户端
     * @param $data
     */
    private function sendToAllClient($data, $sock){
        $this->writefds = $this->readfds;
        unset($this->writefds[0]);
        $string = $this->encode( $this->names[ $this->getKey($sock) ] ." : ".$data);
        foreach($this->writefds as $client){
            if( $client == $sock){
                $data = $this->encode("my : ".$data);
                socket_write($client, $data);
            }else{
                socket_write($client, $string);
            }
        }
    }

    private function sendToOtherClient($data, $sock){
        $this->writefds = $this->readfds;
        unset($this->writefds[0]);
        $data = $this->encode($data);
        foreach($this->writefds as $client){
            if( $client != $sock){
                socket_write($client, $data);
            }
        }
    }
    /**
     * 发送给客户端前封装
     * @param string $msg
     * @return string
     */
    private function encode( $msg = ''){
        $head = str_split($msg, 125);
        if (count($head) == 1){
            return "\x81" . chr(strlen($head[0])) . $head[0];
        }
        $info = "";
        foreach ($head as $value){
            $info .= "\x81" . chr(strlen($value)) . $value;
        }
        return $info;
    }

	/**
	 * 解码客户端发送过来的信息
	 * @param binary $buffer 客户端传来的信息
	 * @return String $decoded 解码后的字符串
	*/
    private function decode( $buffer ){
        $masks = $data = $decoded = null;
        // $buffer[1] 第二个bit 内容为 mask + Payload len
        // ord() 把ASCII转换成数字
        // 1100 1100 & 0111 1111 变向去除第一位mask获得 Payload len
        $len = ord($buffer[1]) & 127;
        // Payload length 0 - 126
        // mask 第5个bit开始长度为4
        // data 第9个bit开始
        if ($len === 126) {
            $masks = substr($buffer, 4, 4);
            $data = substr($buffer, 8);
        }
        // Payload length 0 - 127
        // mask 第11个bit开始长度为4
        // data 第15个bit开始
        else if ($len === 127) {
            $masks = substr($buffer, 10, 4);
            $data = substr($buffer, 14);
        }
        // Payload length 0 - 125
        // mask 第3个bit开始长度为4
        // data 第7个bit开始
        else {
            $masks = substr($buffer, 2, 4);
            $data = substr($buffer, 6);
        }
        // 根据掩码获得内容
        for ($index = 0; $index < strlen($data); $index++) {
            $decoded .= $data[$index] ^ $masks[$index % 4];
        }
        return $decoded;
    }

    /**
     * 服务端控制台信息
     * @param $string
     */
    private function console($string){
        echo $string."\n";
    }

    /**
     * 返回对应的key
     * @param $client
     * @return mixed
     */
    private function getKey($client){
        return array_search($client, $this->readfds);
    }
}
?>