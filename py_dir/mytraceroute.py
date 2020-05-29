import socket;
import struct;
import random;
import time;
import select;
import math;
import sys;

ICMP_ECHO_REQUEST = 8
ICMP = socket.getprotobyname('icmp')

"""
Given the bytes array, it calculates the checksum and returns it.
"""
def checksum(source_string):
    # I'm not too confident that this is right but testing seems to
    # suggest that it gives the same answers as in_cksum in ping.c.
    sum = 0
    count_to = len(source_string)
    count = 0
    while count < count_to:
        this_val = (source_string[count + 1])*256 + (source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff # Necessary?
        count = count + 2
    if count_to < len(source_string):
        sum = sum + (source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

"""
Создает новый пакет для данного ID
"""
def create_packet(id):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    # b - signed char, H - unsigned short, h - signed
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = ''
    
    my_checksum = checksum(header + data.encode('utf-8'))

    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
            socket.htons(my_checksum), id, 1)
    return header + data.encode('utf-8')

"""
0 - таймаут
адрес и время - все ок
"""
def receive(my_socket, packet_id, time_sent, timeout):
    time_left = timeout
    while True:
        # select.select(rlist, wlist, xlist[, timeout])
        # rlist: wait until ready for reading
        # wlist: wait until ready for writing
        # xlist: wait for an “exceptional condition”
        ready = select.select([my_socket], [], [], time_left)
        if ready[0] == []: # Timeout
            return 0

        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(1024)
        # Последние 8 байт - заголовок отправленного пакета 
        icmp_header = rec_packet[-8:]
        p_type, code, checksum, p_id, sequence = struct.unpack(
                'bbHHh', icmp_header)
        if p_id == packet_id:
            total_time_ms = (time_received - time_sent) * 1000
            # Округляем время
            total_time_ms = math.ceil(total_time_ms)
            return (addr[0], total_time_ms)

        time_left -= time_received - time_sent
        if time_left <= 0:
            return 0

"""
0 - таймаут
адрес и время - все ок
"""
def send_one(host, ttl, sock):
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    # Максимум для unsigned short - 65535. 
    # ID пакета <= 65536
    packet_id = int(random.random() * 65535)
    packet = create_packet(packet_id)
    while packet:
        # ICMP не использует порт, но у ф-ции есть аргумент для порта
        sent = sock.sendto(packet, (host, 1))
        packet = packet[sent:]

    res = receive(sock, packet_id, time.time(), timeout)
    return res

"""
Возвращает флаг о достижении конечного адреса и выводит на экран
результат.
"""
def send_three(host, ttl, sock):
    # Отправка 3-x эхо-запросов
    try_1 = send_one(host, ttl, sock)
    try_2 = send_one(host, ttl, sock)
    try_3 = send_one(host, ttl, sock)

    src_addr = None
    src_name = None

    if try_1 == 0:
        try_1_str = '*'
    else:
        try_1_str = str(try_1[1]) + ' ms'
        src_addr = try_1[0]
    if try_2 == 0:
        try_2_str = '*'
    else:
        try_2_str = str(try_2[1]) + ' ms'
        src_addr = try_2[0]
    if try_3 == 0:
        try_3_str = '*'
    else:
        try_3_str = str(try_3[1]) + ' ms'
        src_addr = try_3[0]

    if src_addr == host:
        dest_reached = True
    else:
        dest_reached = False

    # Проверка удалось ли получить адрес
    if src_addr == None:
        # Если нет, то таймаут 
        print("%-3d%-7s%-7s%-7s%-15s" % (ttl, try_1_str, try_2_str, try_3_str, 'Timeout'))
    else:
        # Если удалось, то пытаемся получить имя хоста
        try: 
            src_name,_,_ = socket.gethostbyaddr(src_addr)
            src_name = '{'+src_name+'}'
            print("%-3d%-7s%-7s%-7s%-15s%-40s" % (ttl, try_1_str, try_2_str, try_3_str, src_addr, src_name))
        except  Exception as err:
            print("%-3d%-7s%-7s%-7s%-15s" % (ttl, try_1_str, try_2_str, try_3_str, src_addr))

    return dest_reached

#-----------------------------#
# Выполнение начинается здесь #

if len(sys.argv) <= 1:
    print('\nProvide a hostname.')
    sys.exit(1)

# mytracerute.py host num_hops
# [0]            [1]  [2]
dest_addr = sys.argv[1]
if len(sys.argv) == 3:
    try:
        max_hops = int(sys.argv[2])
    except Exception as err:
        print('\nProvide a valid max. hops value.')
        sys.exit(1)
else:
    max_hops = 30

# Домен -> IP
try:
    host = socket.gethostbyname(dest_addr)
except Exception as err:
    print('\nProvide a valid hostname.')
    sys.exit(1)    

timeout = 3

print('\nTraceroute to ' + dest_addr + ' (' + host + ') with ' + str(max_hops) +
      ' max. hops\n')
try:
    # Главный цикл
    ttl = 1
    dest_reached = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP)
    while ttl <= max_hops and not dest_reached:
        dest_reached = send_three(host, ttl, sock)
        ttl += 1
    sock.close()
except Exception as err:
    print(err)
except KeyboardInterrupt as err:
    print(err)

print('\nTraceroute done.')