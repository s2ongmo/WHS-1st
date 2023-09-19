[WHS][PCAP Programming] 9반  유성모(2285) 

- 과제  목표> 

C, C++  기반  PACP API를  활용해  PACKET의  정보를  출력하는  프로그램  작성 

- Ethernert Header: src mac, dst mac  출력 
- IP Header: src ip, dst ip  출력 
- TCP Header: src port, dst port  출력 
- TCP Message  출력 
- TCP protocol만  출력 
- 목차> 
  - 이더넷  데이터그램  구조 
  - IP  데이터그램  구조 
  - TCP  데이터그램  구조 
  - 실제  패킷  확인 
  - 코드  리뷰 
- 소스코드  주소> [https://github.com/s2ongmo/packetcapture.git ](https://github.com/s2ongmo/packetcapture.git) 데이터그램  조사는  IPv4를  대상으로  진행했습니다. ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.001.png)

패킷  각  계층의  데이터그램(헤더+데이터)을  스니핑  하기  위해  데이터그램  구조를  알아보자. 

1. 이더넷  데이터그램  구조 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.002.jpeg)

출처 [^1]

libpcap을  사용해  패킷을  캡처할  때  NIC(Network Interface Card)는  Preamble/SFD와 FCS는  생략하고  준다.[^2] 

따라서  우리는  \*packet을  사용해  바로  이더넷  dst  주소에  접근할  수  있다. 

\*packet은  pcap\_open\_live()로  반환된  \*handle과  pcap\_loop()에  사용자가  정의한  콜 백(callback)  함수(got\_packet)으로  인해  캡처된  패킷의  첫  주소(dst mac)가  반환된다. 

예시로  콜백  함수는  이렇게  정의할  수  있다. 

void my\_callback(u\_char \*user\_data, const struct pcap\_pkthdr \*pkthdr, const u\_char \*packet) { 

`    `printf("Packet length: %d\n", pkthdr->len);     for(int i = 0; i < pkthdr->len; i++) { 

`        `printf("%02x ", packet[i]); 

`    `} 

`    `printf("\n"); 

} 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.003.png)

u\_char   \*user\_data![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.004.png)

이는  pcap\_loop, pcap\_dispatch  함수  호출  시에  전달된  마지막  인자로,  사용자가  임의로 전달할  수  있는  데이터를  가리킨다.  사용자  정의  데이터를  콜백에  전달하고  싶을  때  이  인자 를  활용할  수  있다. 

const struct pcap\_pkthdr \*pkthdr ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.005.png)

이  구조체는  캡처된  패킷의  메타  데이터를  포함한다.  주요  멤버는 

struct timeval ts:  패킷이  캡처된  정확한  시간  (초와  마이크로초) bpf\_u\_int32 len:  패킷의  실제  길이 

bpf\_u\_int32 caplen:  캡처된  패킷의  길이  (이  길이는  len보다  작거나  같음) 

const u\_char \*packet![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.006.png)

캡처된  패킷의  실제  데이터를  가리키는  포인터.  이  데이터는  콜백  함수  내에서  분석  및  처리 할  수  있다. 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.007.png)

packet은  스트림  데이터  형식이다. (struct ethheader \*)로  형  변환  하여  컴파일러의  오류 를  줄여줄  수  있다.  그리고  \*eth에  담으면  \*eth로  이더넷  헤더를  핸들링  할  수  있다. 

ethheader  구조체는  직접  정의할  수도  있지만  정의돼  있는  <netinet/if\_ether.h> ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.008.png)라이브러리를  사용해  핸들링  할  수도  있다. 

마찬가지로  <netinet/ip.h> <netinet/tcp.h>  를  사용하면  ip, tcp  헤더를  핸들링  할  수  있다.

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.009.png)

2. IP  데이터그램  구조 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.010.png)

출처[^3]

버전(Version): 4 비트 ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.011.png)

IPv4 는  4  로  표현되며  IPv6 는  6 으로  표현된다. 

인터넷  헤더  길이(Internet Header Length): 4 비트 ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.012.png)

32 비트(4 바이트)단위로  표시된다.  이  값이  5 라면  IHL 은  5 \* 4 = 20 바이트이다. 

서비스  유형(Type of Service. TOS): 8 비트 ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.013.png)

패킷의  우선순위를  나타내는  필드로  쓰인다.  과거에는  상위  3 비트(Precedence)  와 

5 비트를  나누어  사용하였지만  현재는  DSCP(Differentiated Services Code Point) 6 비트와  ECN(Explicit Congestion Notification) 2 비트  필드로  쓰인다. 

DSCP 는  패킷  우선순위를  나타내고  ECN 은  네트워크  혼잡도를  나타낸다.  이를  보고 

송신측은  패킷  전송  속도를  조절할  수  있다. 

총  길이(Total Length): 16 비트 ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.014.png)

IP  헤더에  포함되며  IP  데이터그램  전체(헤더+데이터)의  길이를  의미한다. 16 비트  최대 

65,535  바이트의  데이터그램  길이를  지정할  수  있다. 

생존시간  (Time To Live) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.015.png)크기: 8비트 

정의:  패킷이  네트워크  내에서  살아있을  수  있는  시간  또는  홉  수를  나타낸다.  패킷이  네트워 크  내에서  너무  오래  돌아다니는  것을  방지하기  위해  TTL  값이  하나씩  감소된다.  값이  0이 되면  패킷은  폐기된다. 

초기  값은  64  또는  128로  설정된다. 

용도:  무한  루프로  인한  패킷  폭주를  방지하고  패킷의  생명  주기를  제한하는  데  사용된다. 식별자  (Identification) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.016.png)

크기: 16비트 

정의:  각각의  IP  패킷에  유일하게  할당되는  식별  번호. 

용도:  패킷  재조립  시  사용된다.  패킷이  분할되어  전송될  때  원래의  패킷으로  재조립하는  데 필요한  식별  번호  역할을  한다. 

프로토콜  (Protocol ) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.017.png)크기: 8비트 

정의:  다음  계층에  어떤  프로토콜이  사용되는지를  나타낸다.  예를  들어, TCP는  6, UDP는  17 로  나타난다. 

용도:  수신  시스템은  이  필드를  사용하여  패킷의  데이터  부분을  어떻게  처리할지  결정한다. 이  필드의  값에  따라  다음  헤더를  TCP, UDP, ICMP  등으로  해석한다. 

Flags ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.018.png)크기: 3비트 

데이터그램  조각화  관련  플래그를  저장한다.  예를  들어, "Don't Fragment (DF)"  플래그는 데이터그램이  조각나지  않도록  지시하며, "More Fragments (MF)"  플래그는  뒤따르는  추가 조각이  있는지  여부를  나타낸다. 

예시: 

010: DF 플래그가 설정, MF 플래그가 설정되지 않음. ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.019.png)001: MF 플래그만 설정. ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.020.png)

000: 두 플래그 모두 설정되지 않음. ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.021.png)

Fragment Offset ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.022.png)

크기: 13비트 

데이터그램이  조각화될  때,  각  조각의  시작  바이트  위치를  나타낸다.  첫  번째  조각의  offset 은  0이다. 

Header Checksum ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.023.png)크기: 16비트 

IP  헤더의  오류를  검출하는  데  사용되는  체크섬  값.  수신자  측에서  이  체크섬을  다시  계산하 여  송신자가  계산한  체크섬과  비교한다.  일치하지  않으면  헤더에  오류가  있다고  판단한다. 

Source IP Address ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.024.png)크기: 32비트 

패킷을  보내는  출발  장치의  IP  주소. Destination IP Address![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.025.png)

크기: 32비트 

패킷을  받는  도착  장치의  IP  주소. Options (if present): ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.026.png)

크기:  가변  길이 

IP  헤더의  기본  길이를  초과하는  추가  정보를  제공하는  선택적  필드.  예를  들어,  라우트,  타 임스탬프,  보안  등에  대한  정보를  포함할  수  있다. 

Fragment Offset 과  Identification 의  차이점: ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.027.png)

Fragment Offset:  패킷이  분할될  때  각  조각의  시작  바이트  위치를  나타내는  값이다.  첫 조각의  경우  ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.028.png)offset은  0이다. 

Identification  (ID):  모든  데이터그램  (분할되었든,  그렇지  않든)에  고유한  ID를  부여하는 값이다![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.029.png).  이  값은  데이터그램이  분할될  때  모든  조각에  동일하게  포함되어  조각의  재조립  시 원래  데이터그램을  식별하는  데  사용된다. 

3. TCP  데이터그램  구조 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.030.jpeg)

출처[^4]

Source Port (16 bits) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.031.png)

패킷을  송신하는  기기의  포트  번호. 

예: 56234 

Destination Port (16 bits) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.032.png)

패킷을  수신하는  기기의  포트  번호. 

예: 80 (HTTP  기본  포트) 

**Sequence Number (32 bits) & Acknowledgment Number (32 bits)** ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.033.png)이  번호들은  데이터  전송의  순서와  데이터의  무결성을  보장하는  데  사용된다. 

Sequence Number는  현재  세그먼트에  포함된  첫  번째  바이트의  번호이다.  

Acknowledgment Number는  수신측이  다음에  기대하는  바이트의  번호를  나타내며,  이는 모든  이전  바이트가  이미  올바르게  수신되었음을  의미한다. 

Data Offset (4 bits) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.034.png)

TCP  헤더의  길이를  나타낸다.  이  필드는  TCP  헤더가  몇  개의  32비트로  구성되어  있는지 를  나타낸다. 

예: 5 (표준  TCP  헤더는  5 x 32비트,  즉  20  바이트) 

Reserved (3 bits) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.035.png)

현재  사용되지  않으며,  나중의  사용을  위해  예약되어  있다.  항상  0으로  설정된다. 

Flags (9 bits) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.036.png)

URG: Urgent pointer가  유효하다는  것을  나타내는  플래그. 

ACK: Acknowledgment  필드가  유효하다는  것을  나타낸다. PSH:  수신한  데이터를  가능한  빨리  애플리케이션에  전달하도록  요청. RST:  연결  리셋  요청. 

SYN:  연결  설정  요청. 

FIN:  연결  종료  요청. 

Window Size (16 bits) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.037.png)

수신자가  현재  수신할  준비가  된  데이터의  양을  바이트  단위로  나타낸다. 

이  필드는  수신측  버퍼의  사용  가능한  공간을  나타낸다.  송신측은  이  정보를  바탕으로  데이터 를  보내는  속도를  조절할  수  있다. 

Checksum (16 bits) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.038.png)

헤더와  데이터의  오류  검사를  위한  값.  송신  시  생성되고  수신  시  확인된다. 

Urgent Pointer (16 bits) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.039.png)

URG  플래그가  설정되면  이  필드는  세그먼트  내의  긴급한  데이터의  마지막  바이트를  가리킨 다. 

Options (variable length, up to 40 bytes) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.040.png)

다양한  선택적  기능,  예를  들어  최대  세그먼트  크기  (MSS)나  타임스탬프  등을  지정. 

Data (variable length) ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.041.png)전송되는  실제  데이터. 

4. 실제  패킷  확인 

지금까지  TCP/IP  각  계층의  데이터그램  구조를  알아봤다.  이제  직접  TCP  요청을  보내고 와이어샤크를  통해  패킷을  확인해보도록  하자.

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.042.png)

TCP  연결  요청과  메시지를  naver.com 80번  포트로  보내고  메시지를  받았다. 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.043.png)

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.044.png)

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.045.png)

[Stream index: 2] ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.046.png)

스트림  인덱스는  패킷  세션  고유번호이다. 1개의  패킷을  분할하면  모두  같은  스트림  인덱스를 갖게  되고  Follow -> TCP stream을  따라가면  해당  세션에  대한  모든  패킷을  볼  수  있다. 

[Conversation completeness: Complete, WITH\_DATA (31)] ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.047.png)TCP  패킷  교환이  정상적으로  이루어졌음을  나타낸다.[^5] 

[TCP Segment Len: 0] ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.048.png)

TCP  패킷에  데이터가  없다는  뜻.  

TCP Segment Len이  0인  경우:  

- SYN  패킷: 3way handshake의  1번째  단계에서  SYN  플래그만  설정되었을  때 
- FIN  패킷:  연결  종료를  알리는  패킷 
- ACK  패킷:  수신된  데이터를  확인하는  용도로  전송되는  패킷 
- RST  패킷:  연결  리셋을  지시하는  패킷 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.049.jpeg)

데이터를  보낸  패킷을  보면  [TCP Segment Len: 6]을  확인할  수  있다. 이제  ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.050.png)IP  패킷을  보자. 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.051.jpeg)

IPv4, DSCP, Total Length, TTL, checksum  등  데이터그램  구조에서  조사한  내용을  볼 수  있다. 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.052.jpeg)

TCP msg ‘print’  가  정확히  3way handshake  후에  출력되는  것을  확인할  수  있다. 

5. 코드  리뷰 
- main  함수 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.053.png)

pcap\_t \*handle; ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.054.png)

pcap\_t  구조체  타입  포인터  handle  선언. 

struct bpf\_program fp; ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.055.png)

bpf filter(tcp)를  바이트  코드로  변환한  값을  저장할  bpf\_program  구조체  변수. char filter\_exp[] = “tcp”; ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.056.png)

tcp  프로토콜만  캡처하게  필터링  해줄  변수. 

handle = pcap\_open\_live("eth0", BUFSIZ, 1, 1000, errbuf); ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.057.png)

eth0  장치로  들어오는  패킷을  읽는다.  읽은  패킷은  handle에  담긴다. 

1000ms(1초)후에  타임아웃  되며  실패(NULL)값이  반환되면  errbuf에  에러  메시지가  반환 된다. 

pcap\_compile(handle, &fp, filter\_exp, 0, net); ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.058.png)

`   `if (pcap\_setfilter(handle, &fp) !=0) { ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.059.png)

`      `pcap\_perror(handle, "Error:"); ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.060.png)

`      `exit(EXIT\_FAILURE); ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.061.png)

} ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.062.png)

읽은  패킷을  컴파일  한다. filter\_exp  값이  바이트  코드로  바뀌어  fp로  담긴다. 

fp에  바뀐  바이트  코드로  setfilter()에서  필터링을  진행한다.  성공하면  0을  반환한다. pcap\_loop(handle, -1, got\_packet, NULL); ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.063.png)

handle에  읽힌  패킷을  -1,  무한으로  캡처한다.  캡처될때마다  콜백함수  got\_packet을  호출 하고  콜백함수에  추가  데이터를  전달하지  않는다. (NULL) 

- got\_packet(callback)  함수 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.064.png)

iph\_protocol == IPROTO\_TCP   IP헤더의  프로토콜  값이  TCP일때만  출력한다. ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.065.png)

또  tcp\_data는  tcp  데이터그램의  데이터  위치가  담기는데,  그  위치는  packet(이더넷  헤더 시작  위치) + (이더넷  헤더  크기=IP  헤더  시작) + (IP헤더  길이(4바이트  단위) \* 4) +  (TCP OffSet  상위  4비트  \* 4)  이다. TCP Offset  상위  4비트에  TCP  헤더의  길이가  담기기  때문 이다. 

코드  상단  선언부에는  이렇게  선언돼  있다. 

// tcp\_offx2  에서  상위  4비트만  추출 ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.066.png)

#define TH\_OFF(th)       (((th)->tcp\_offx2 & 0xf0) >> 4)   ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.067.png)

마지막으로  출력  부분이다. 

![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.068.png)

눈여겨  볼  점은  ntoa와  ntohs함수를  사용했다는  건데 ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.069.png)![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.070.png)

ntoa(): struct in\_addr  타입의  IPv4  주소를  표준  점으로  구분된  문자열  형식으로  변환한다. ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.071.png)ntohs(): 16비트의  숫자를  네트워크  바이트  순서에서  호스트  바이트  순서로  변환한다. ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.072.png)

즉,  빅  엔디안(패킷  데이터)에서  리틀  엔디안(리눅스)으로  변환한다. ![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.073.png)

이번  과제를  하면서  공부해야  될  게  많았다. 

- TCP  연결이  되기  위해서  3way handshake가  성공해야  한다.  성공하지  못하면  데이터를 못  보낸다.  이걸  알고  있었는데  막상  nc로  사용할  때  연결이  되지도  않았는데  메시지를  보내 는  삽질을  했다. 
- 각  계층의  데이터그램  구조를  상세히  알게  됐다.  전에는  패킷을  들여다  봐도  무슨  의미인지 몰랐는데  이제  대충  감이라도  잡을  수  있게  됐다.  하지만  완벽히  알려면  아직  더  공부해야  한 다. 
- 구조체  포인터를  어떻게  사용해야  할지  감을  잡을  수  있었고  형  변환에  대해  자세히  알  수 있었다. 
- 좋은  과제를  내주셔서  감사드립니다.  
- 참고자료> 

CHAT GPT 

[https://blog.naver.com/sujunghan726/220315439853 ](https://blog.naver.com/sujunghan726/220315439853)[https://dany-it.tistory.com/331 ](https://dany-it.tistory.com/331)[https://networklessons.com/quality-of-service/ip-precedence-dscp-values ](https://networklessons.com/quality-of-service/ip-precedence-dscp-values)[https://www.freesoft.org/CIE/Course/Section3/7.htm ](https://www.freesoft.org/CIE/Course/Section3/7.htm)[https://github.com/the-tcpdump-group/libpcap.git ](https://github.com/the-tcpdump-group/libpcap.git)[https://evan-moon.github.io/2019/11/10/header-of-tcp/ ](https://evan-moon.github.io/2019/11/10/header-of-tcp/)<https://ehclub.co.kr/2262>

<https://velog.io/@khu147/handshake>![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.074.png)

[https://velog.io/@dyunge_100/Network-TCPIP - 4%EA%B3%84%EC%B8%B5%EC%97%90-%EB%8C%80%ED%95%98%EC%9 7%AC ](https://velog.io/@dyunge_100/Network-TCPIP-4%EA%B3%84%EC%B8%B5%EC%97%90-%EB%8C%80%ED%95%98%EC%97%AC)![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.075.png)

[https://velog.io/@zioo/IP%ED%97%A4%EB%8D%94-%ED%98%95%EC%8B% 9D%EA%B3%BC-%EC%9D%98%EB%AF%B8-%EC%9A%94%EC%95%BD](https://velog.io/@zioo/IP%ED%97%A4%EB%8D%94-%ED%98%95%EC%8B%9D%EA%B3%BC-%EC%9D%98%EB%AF%B8-%EC%9A%94%EC%95%BD)![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.076.png)

[https://link2me.tistory.com/43 ](https://link2me.tistory.com/43)<https://t-okk.tistory.com/77>![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.077.png)

[https://access.redhat.com/documentation/ko - kr/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administrat ion_guide/sect-virtual_networking-directly_attaching_to_physical_interface](https://access.redhat.com/documentation/ko-kr/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/sect-virtual_networking-directly_attaching_to_physical_interface)![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.078.png)

[https://m.blog.naver.com/ndb796/221053780860 ](https://m.blog.naver.com/ndb796/221053780860)[https://myblog.opendocs.co.kr/archives/1230 ](https://myblog.opendocs.co.kr/archives/1230)[https://blog.silnex.kr/bobnetwork-libpcapwinpcap-programing/ ](https://blog.silnex.kr/bobnetwork-libpcapwinpcap-programing/)<https://velys-log.tistory.com/4>

[https://tmdgus.tistory.com/121 ](https://tmdgus.tistory.com/121)[https://m.blog.naver.com/shw20319/20191826292 ](https://m.blog.naver.com/shw20319/20191826292)<https://blog.naver.com/PostView.naver?blogId=jkf941&logNo=220583044439>![](Aspose.Words.4da9da52-15d0-4846-93ec-2ba8412f095d.079.png)

[^1]: `  `[https://velog.io/@moonblue/%EC%9D%B4%EB%8D%94%EB%84%B7-%ED%94%84%EB%A0%88%EC%9E%84 - Ethernet-Frame ](https://velog.io/@moonblue/%EC%9D%B4%EB%8D%94%EB%84%B7-%ED%94%84%EB%A0%88%EC%9E%84-Ethernet-Frame)
[^2]: 일반적인 NIC는 생략하지만 특수한 NIC를 이용하면 볼 수 있다. 
[^3]: https://www.freesoft.org/CIE/Course/Section3/7.htm 
[^4]: https://dany-it.tistory.com/331 
[^5]: https://www.cellstream.com/2023/04/14/zero-to-hero-wireshark-tcp-conversation-completeness/ 