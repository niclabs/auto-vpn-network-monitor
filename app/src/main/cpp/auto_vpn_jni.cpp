#include <string>
#include <unordered_map>
#include <sstream>
#include <jni.h>
#include <cstdio>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <android/log.h>
#include <cstring>
#include <cerrno>
#include <cinttypes>
#include <iostream>
#include <fstream>
#include <csetjmp>
#include <sys/syscall.h>
#include "vpn_connection.h"


bool first_execution = true;
bool VPN_BYTES_AVIALABLE = true;
int vpnFd;
struct epoll_event fd_ev;
int epollFd;

static std::unordered_map<std::string, UdpConnection*> udpMap;
static std::unordered_map<std::string, TcpConnection*> tcpMap;
static std::vector<std::string *> keys;

pthread_mutex_t mtx_tcpmap, mtx_udpmap;
pthread_cond_t cond_tcpmap, cond_udpmap, cond_fd;

static std::unordered_map<int, std::string> packageMap;

jlong env_timestamp;
JavaVM* jvm;
JNIEnv* jniEnv;
jobject jObject;
jmethodID protectMethod;
jmethodID packageNameMethod;
jmethodID ownerApplicationMethod;

template <typename T>
std::string to_string(T value){
    std::ostringstream os ;
    os << value ;
    return os.str() ;
}


/* Simulates Android VpnService protect() function in order to protect
  raw socket from VPN connection. So, according to Android reference,
  "data sent through this socket will go directly to the underlying network,
  so its traffic will not be forwarded through the VPN"*/
int protect(int sd){
    jboolean res = jniEnv->CallBooleanMethod(jObject, protectMethod, sd);
    if(res){
        //__android_log_print(ANDROID_LOG_ERROR, "JNI ","protected socket: %d", sd);
        return 1;
    }
    return 0;
}

std::string getPackageName(int uid){
    if (packageMap.count(uid) == 0) {
        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "uid %d not found", uid);

        auto res = (jstring) jniEnv->CallObjectMethod(jObject, packageNameMethod, uid);
        const char *utfChars = jniEnv->GetStringUTFChars(res, 0);
        std::string package = std::string(utfChars);
        jniEnv->ReleaseStringUTFChars(res, utfChars);
        packageMap.insert(std::make_pair(uid, package));
        return package;
    } else
        return packageMap.at(uid);
}

void broadcastUdp(UdpConnection* connection) {
    pthread_mutex_lock(&mtx_udpmap);
    connection->busy = false;
    pthread_cond_broadcast(&cond_udpmap);
    pthread_mutex_unlock(&mtx_udpmap);
}

void broadcastTcp(TcpConnection* connection) {
    pthread_mutex_lock(&mtx_tcpmap);
    connection->busy = false;
    pthread_cond_broadcast(&cond_tcpmap);
    pthread_mutex_unlock(&mtx_tcpmap);
}

std::string getApplication(const char *protocol, in_addr sourceIp, uint16_t sourcePort, in_addr destIp, uint16_t destPort) {
    std::string package = "";

    if (android_get_device_api_level() < 29) {
        //const char *grepString = "cat /proc/net/%s* | grep -m 1 -oEi '^([[:blank:]]*)([[:digit:]]+): ([0-9A-F]+):%04X ([0-9A-F]*%X):%04X (..) (([0-9A-F]+):([0-9A-F]+) ){2}([0-9A-F]+)([[:blank:]]+)([[:digit:]]+)' | grep -oEi '([[:digit:]]+)$'";
        const char *grepString = "cat /proc/net/%s* | grep -m 1 -oEi '^([[:blank:]]*)([[:digit:]]+): ([0-9A-F]+):%04X ([0-9A-F]+):([0-9A-F]+) (..) (([0-9A-F]+):([0-9A-F]+) ){2}([0-9A-F]+)([[:blank:]]+)([[:digit:]]+)' | grep -oEi '([[:digit:]]+)$'";
        char buffer[300];
        int n;
        n = sprintf(buffer, grepString, protocol, sourcePort);//, destIp, destPort);

        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "%s", buffer);

        FILE *fp = popen(buffer, "r");

        if (fp != NULL) {
            char buf[20];

            if (fgets(buf, 20, fp) != NULL) {
                package = getPackageName(std::stoi(buf));
            }
            pclose(fp);
        }
    }
    else {
        JNIEnv* threadEnv;
        bool shouldDetach = false;

        if (jvm->GetEnv((void**)&jniEnv, JNI_VERSION_1_6) == JNI_EDETACHED) {
            //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "not attached");
            shouldDetach = true;
            jvm->AttachCurrentThread(&threadEnv, NULL);
        } else {
            threadEnv = jniEnv;
            //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "already attached");
        }

        jstring jSourceIp = threadEnv->NewStringUTF(inet_ntoa(sourceIp));
        jstring jDestIp = threadEnv->NewStringUTF(inet_ntoa(destIp));
        jstring jProtocol = threadEnv->NewStringUTF(protocol);

        auto res = (jstring) threadEnv->CallObjectMethod(jObject, ownerApplicationMethod, jProtocol, jSourceIp, sourcePort, jDestIp, destPort);

        const char *utfChars = jniEnv->GetStringUTFChars(res, 0);
        package = std::string(utfChars);
        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "cat package java %s", utfChars);
        threadEnv->DeleteLocalRef(jSourceIp);
        threadEnv->DeleteLocalRef(jDestIp);
        threadEnv->DeleteLocalRef(jProtocol);
        if (shouldDetach)
            jvm->DetachCurrentThread();
    }

    return package;
}

/* Get file descriptor number from Java object FileDescriptor */
int getFileDescriptor(JNIEnv* env, jobject fileDescriptor) {
    jint fd = -1;

    jclass fdClass = env->FindClass( "java/io/FileDescriptor");
    if (fdClass != nullptr) {
        jfieldID fdClassDescriptorFieldID = env->GetFieldID(fdClass,"descriptor", "I");
        if (fdClassDescriptorFieldID != nullptr && fileDescriptor != nullptr) {
            fd = env->GetIntField(fileDescriptor, fdClassDescriptorFieldID);
        }
    }
    //__android_log_print(ANDROID_LOG_ERROR, "JNI ","VPN fd: %d", fd);

    return fd;
}

sigjmp_buf jbuf;

void sig_handler(int sig) {
    //__android_log_print(ANDROID_LOG_ERROR, "JNI", "got signal %d (%s)\n", sig, sys_siglist[sig]);

    siglongjmp(jbuf, 1);
}

void error(const char *s){
    perror(s);
    RUNNING = false;
    exit(EXIT_FAILURE);
}

void receivePackets(VpnConnection *connection, int vpnFd);
void connectSocket(TcpConnection *connection, int vpnFd);
void getTcpInfo(TcpConnection *connection);
void getUdpInfo(UdpConnection *connection);
std::string clearTcpConnection(TcpConnection *tcpConnection, bool save);

void sendPackets(VpnConnection *connection, int vpnFd) {
    if(connection->getProtocol() == IPPROTO_UDP) {

        auto *udpConnection= (UdpConnection*) connection;
        int udpSd= udpConnection->getSocket();

        while (!udpConnection->queue.empty()){

            uint8_t* ipPacket = udpConnection->queue.front();
            auto *ipHdr= (struct ip*) ipPacket;
            int ipHdrLen = ipHdr->ip_hl * 4;
            int packetLen = ntohs(ipHdr->ip_len);
            int udpHdrLen = 8;

            int payloadDataLen = packetLen - ipHdrLen - udpHdrLen;
            uint8_t* packetData = ipPacket + ipHdrLen + udpHdrLen;
            int bytesSent = send(udpSd, packetData, payloadDataLen, 0);

            free(ipPacket);
            udpConnection->queue.pop();

            if (bytesSent < 0) {
                udpConnection->end_time = udpConnection->lastTime;
                getUdpInfo(udpConnection);
                //epoll_ctl(epollFd, EPOLL_CTL_DEL, udpSd, &udpConnection->ev);
                close(udpSd);
                pthread_mutex_lock(&mtx_udpmap);
                std::string keyConnection = udpConnection->key;
                delete udpConnection;
                udpMap.erase(keyConnection);
                pthread_cond_broadcast(&cond_udpmap);
                pthread_mutex_unlock(&mtx_udpmap);
                return;
            }
            else
                udpConnection->tx_bytes += bytesSent;
        }
        epoll_ctl(epollFd, EPOLL_CTL_MOD, udpSd, &udpConnection->ev);
        broadcastUdp(udpConnection);
    }

    else if(connection->getProtocol() == IPPROTO_TCP){

        auto *tcpConnection = (TcpConnection*) connection;

        if(!tcpConnection->connected){
            //__android_log_print(ANDROID_LOG_ERROR, "JNI", "sendPacket: %s not connected", tcpConnection->key.c_str());
            tcpConnection->connected = true;
            /*if (tcpConnection->app.empty())
                tcpConnection->app = getApplication("tcp", tcpConnection->sourcePort,
                                                    tcpConnection->destIp, tcpConnection->destPort);*/
        }

        int tcpSd = tcpConnection->getSocket();

        while (!tcpConnection->queue.empty()){

            uint8_t* ipPacket = tcpConnection->queue.front();

            //TODO: ipv6
            auto *ipHdr= (struct ip*) ipPacket;
            uint32_t ipHdrLen = ipHdr->ip_hl * 4;
            uint16_t packetLen = ntohs(ipHdr->ip_len);

            auto* tcpHdr = (tcphdr*) (ipPacket + ipHdrLen);

            uint16_t tcpHdrLen = tcpHdr->doff * 4;
            uint16_t payloadDataLen = packetLen - ipHdrLen - tcpHdrLen;

            if(ntohl(tcpHdr->seq) >= tcpConnection->currAck) {

                uint8_t* packetData = ipPacket + ipHdrLen + tcpHdrLen;
                int bytesSent = 0;

                bytesSent += send(tcpSd, packetData, payloadDataLen, 0);

                if (bytesSent > 0)
                    tcpConnection->tx_bytes += bytesSent;
                //TODO: socket error management

                if(bytesSent < payloadDataLen){
                    tcpConnection->ev.events = EPOLLIN | EPOLLOUT | EPOLLONESHOT;
                    break;
                } else{
                    free(ipPacket);
                    tcpConnection->queue.pop();
                    tcpConnection->currAck += bytesSent;
                    tcpConnection->receiveAck(vpnFd, TH_ACK);
                }
            } else{
                free(ipPacket);
                tcpConnection->queue.pop();
            }
        }
        if (tcpConnection->queue.empty()){
            tcpConnection->ev.events = EPOLLIN | EPOLLONESHOT;
        }

        if (epoll_ctl(epollFd, EPOLL_CTL_MOD, tcpConnection->getSocket(), &tcpConnection->ev) == -1){
            if(RUNNING)
                error("epoll_ctl: read_sock");
        }

        broadcastTcp(tcpConnection);
    }
    else{
    }
}

void getTcpInfo(TcpConnection* tcpConnection){
    int tcpSd= tcpConnection->getSocket();
    struct tcp_info ti;
    socklen_t tisize = sizeof(ti);
    getsockopt(tcpSd, IPPROTO_TCP, TCP_INFO, &ti, &tisize);

    /* open a file and write results into it*/
    std::ofstream myfile ("report_tcp_info.csv", std::ios_base::app);
    if (myfile.is_open())
    {
        myfile << "tcp," << tcpConnection->key << ",";
        myfile << std::fixed << tcpConnection->start_time.tv_sec << "," << tcpConnection->start_time.tv_usec << ",";
        myfile << std::fixed << tcpConnection->end_time.tv_sec << "," << tcpConnection->end_time.tv_usec << ",";
        myfile << tcpConnection->tx_bytes << "," << tcpConnection->rx_bytes << ",";
        myfile << ti.tcpi_min_rtt << "," << ti.tcpi_rtt << "," << ti.tcpi_rttvar << ",";
        myfile << ti.tcpi_lost << "," << ti.tcpi_snd_cwnd << "," << ti.tcpi_snd_mss << "," << ti.tcpi_rcv_mss << ",";
        myfile << tcpConnection->app << "," << env_timestamp << "\n";

        myfile.close();
    }
}

void getUdpInfo(UdpConnection* udpConnection){
    /* open a file and write results into it*/
    std::ofstream myfile ("report_udp_info.csv", std::ios_base::app);
    if (myfile.is_open())
    {
        myfile << "udp," << udpConnection->key << ",";
        myfile << std::fixed << udpConnection->start_time.tv_sec << "," << udpConnection->start_time.tv_usec << ",";
        myfile << std::fixed << udpConnection->end_time.tv_sec << "," << udpConnection->end_time.tv_usec << ",";
        myfile << udpConnection->tx_bytes << "," << udpConnection->rx_bytes << ",";
        myfile << udpConnection->app << "," << env_timestamp << "\n";
        myfile.close();
    }
}

void receivePackets(VpnConnection *connection, int vpnFd) {
    if(connection->getProtocol() == IPPROTO_UDP) {
        auto *udpConnection = (UdpConnection *) connection;
        int udpSd = udpConnection->getSocket();
        int bytes_read= recv(udpSd, udpConnection->dataReceived, 1500 - 28, 0);
        epoll_ctl(epollFd, EPOLL_CTL_MOD, udpSd, &udpConnection->ev);

        if (bytes_read <= 0) {
            broadcastUdp(udpConnection);
            return;
        }
        udpConnection->rx_bytes += bytes_read;
        gettimeofday(&udpConnection->lastTime, NULL);

        udpConnection->receiveData(vpnFd, bytes_read);

        broadcastUdp(udpConnection);
        return;
    }
    if(connection->getProtocol() == IPPROTO_TCP) {
        bool remainingBytesSent = false;
        auto *tcpConnection = (TcpConnection *) connection;
        int tcpSd = tcpConnection->getSocket();

        int bytesSinceLastAck = tcpConnection->bytesReceived - tcpConnection->bytesAcked();
        int packetLen = -2;

        if (tcpConnection->getAdjustedCurrPeerWindowSize() != 0) {

            if (bytesSinceLastAck >= tcpConnection->getAdjustedCurrPeerWindowSize()) {
                broadcastTcp(tcpConnection);
                epoll_ctl(epollFd, EPOLL_CTL_MOD, tcpSd, &tcpConnection->ev);
                return;
            }
            else if (tcpConnection->lastBytesReceived > 0) {
                packetLen = tcpConnection->lastBytesReceived;
                tcpConnection->lastBytesReceived = 0;
                remainingBytesSent = true;
            }
            else {
                packetLen = recv(tcpSd, tcpConnection->dataReceived, 1500 - 40, 0);
                if (packetLen < 0)
                    __android_log_print(ANDROID_LOG_ERROR, "JNI","error in recv %d %s", errno, strerror(errno));
            }
        }

        epoll_ctl(epollFd, EPOLL_CTL_MOD, tcpSd, &tcpConnection->ev);

        if (packetLen <= 0) {
            if (packetLen == -1) {
                if (errno == EAGAIN) {
                    broadcastTcp(tcpConnection);
                    return;
                }
                else if (errno == ECONNRESET)
                    tcpConnection->receiveAck(vpnFd, TH_RST);
            }
            pthread_mutex_lock(&mtx_tcpmap);
            std::string keyConnection = clearTcpConnection(tcpConnection, true);
            delete tcpConnection;
            tcpMap.erase(keyConnection);

            pthread_cond_broadcast(&cond_tcpmap);
            pthread_mutex_unlock(&mtx_tcpmap);
            return;
        }

        int remainingBytes = tcpConnection->getAdjustedCurrPeerWindowSize() - bytesSinceLastAck;

        if (packetLen > remainingBytes) {
            tcpConnection->lastBytesReceived = packetLen - remainingBytes;
            packetLen = remainingBytes;
        }
        tcpConnection->rx_bytes += packetLen;
        tcpConnection->receiveData(vpnFd, packetLen);

        tcpConnection->currSeq += packetLen;

        tcpConnection->bytesReceived += packetLen;

        if (remainingBytesSent) {
            receivePackets(connection, vpnFd);
        }
        else {
            broadcastTcp(tcpConnection);
        }
    }
}

void* t_receivePacket(void* key){
    //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "thread recv %d", syscall(__NR_gettid));

    std::string* vpnKey = (std::string*) key;

    pthread_mutex_lock(&mtx_udpmap);
    if (udpMap.count(*vpnKey) == 0) {
        pthread_mutex_unlock(&mtx_udpmap);
        pthread_mutex_lock(&mtx_tcpmap);
        if (tcpMap.count(*vpnKey) == 0) {
            pthread_mutex_unlock(&mtx_tcpmap);
            return NULL;
        } else {
            VpnConnection *vpnConnection = tcpMap.at(*vpnKey);
            while (vpnConnection->busy) {
                pthread_cond_wait(&cond_tcpmap, &mtx_tcpmap);
                if (tcpMap.count(*vpnKey) == 0) {
                    pthread_mutex_unlock(&mtx_tcpmap);
                    return NULL;
                }
            }
            vpnConnection->busy = true;
            pthread_mutex_unlock(&mtx_tcpmap);
            receivePackets(vpnConnection, vpnFd);
        }
    } else {
        VpnConnection *vpnConnection = udpMap.at(*vpnKey);
        while (vpnConnection->busy) {
            pthread_cond_wait(&cond_udpmap, &mtx_udpmap);
            if (udpMap.count(*vpnKey) == 0) {
                pthread_mutex_unlock(&mtx_udpmap);
                return NULL;
            }
        }
        vpnConnection->busy = true;
        pthread_mutex_unlock(&mtx_udpmap);
        receivePackets(vpnConnection, vpnFd);
    }
    return NULL;
}

void* t_sendPacket(void* key){
    //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "thread send %d", syscall(__NR_gettid));

    std::string* vpnKey = (std::string*) key;
    pthread_mutex_lock(&mtx_udpmap);
    if (udpMap.count(*vpnKey) == 0) {
        pthread_mutex_unlock(&mtx_udpmap);

        pthread_mutex_lock(&mtx_tcpmap);
        if (tcpMap.count(*vpnKey) == 0) {
            pthread_mutex_unlock(&mtx_tcpmap);
            return NULL;
        } else {
            VpnConnection *vpnConnection = tcpMap.at(*vpnKey);
            while (vpnConnection->busy) {
                pthread_cond_wait(&cond_tcpmap, &mtx_tcpmap);
                if (tcpMap.count(*vpnKey) == 0) {
                    pthread_mutex_unlock(&mtx_tcpmap);
                    return NULL;
                }
            }
            vpnConnection->busy = true;
            pthread_mutex_unlock(&mtx_tcpmap);
            sendPackets(vpnConnection, vpnFd);
        }
    } else {
        VpnConnection *vpnConnection = udpMap.at(*vpnKey);
        while (vpnConnection->busy) {
            pthread_cond_wait(&cond_udpmap, &mtx_udpmap);
            if (udpMap.count(*vpnKey) == 0) {
                pthread_mutex_unlock(&mtx_udpmap);
                return NULL;
            }
        }
        vpnConnection->busy = true;
        pthread_mutex_unlock(&mtx_udpmap);
        sendPackets(vpnConnection, vpnFd);
    }

    return NULL;
}

/*
void connectSocket(TcpConnection *tcpConnection, int vpnFd) {
    tcpConnection->receiveAck(vpnFd, TH_ACK | TH_SYN);
    tcpConnection->connected = true;

    tcpConnection->ev.events = EPOLLIN | EPOLLONESHOT;
    if (epoll_ctl(epollFd, EPOLL_CTL_MOD, tcpConnection->getSocket(), &tcpConnection->ev) == -1)
        error("epoll_ctl: read_sock");

    if (tcpConnection->app.empty())
        tcpConnection->app = getApplication("tcp", tcpConnection->sourcePort,
                                            tcpConnection->destIp, tcpConnection->destPort);

    tcpConnection->busy = false;
    pthread_cond_broadcast(&cond_tcpmap);
}
*/

std::string clearTcpConnection(TcpConnection *tcpConnection, bool save) {
    if (save){
        gettimeofday(&tcpConnection->end_time, nullptr);
        getTcpInfo(tcpConnection);
    }
    int tcpSd = tcpConnection->getSocket();
    //epoll_ctl(epollFd, EPOLL_CTL_DEL, tcpSd, &tcpConnection->ev);
    close(tcpSd);
    //tcpMap.erase(tcpConnection->key);
    //delete tcpConnection;
    return tcpConnection->key;
}

/*
void findUid() {
    pthread_mutex_lock(&mtx_udpmap);
    auto udpIt = udpMap.cbegin();
    while (udpIt != udpMap.cend()) {
        auto curr = udpIt++;
        UdpConnection *udpConnection = curr->second;
        if (udpConnection->app.empty())
            udpConnection->app = getApplication("udp", udpConnection->sourcePort,
                                                udpConnection->destIp, udpConnection->destPort);
    }
    pthread_mutex_unlock(&mtx_udpmap);
    pthread_mutex_lock(&mtx_tcpmap);
    auto tcpIt = tcpMap.cbegin();
    while (tcpIt != tcpMap.cend()) {
        auto curr = tcpIt++;
        TcpConnection *tcpConnection = curr->second;
        if (tcpConnection->app.empty())
            tcpConnection->app = getApplication("tcp", tcpConnection->sourcePort,
                                                tcpConnection->destIp, tcpConnection->destPort);
    }
    pthread_mutex_unlock(&mtx_tcpmap);
}*/

void clearSockets(bool tcp, long timeout) {
    timeval current{};
    gettimeofday(&current, nullptr);
    pthread_mutex_lock(&mtx_udpmap);
    for(auto it = udpMap.begin(); it != udpMap.end();){
        UdpConnection *udpConnection = it->second;
        if (current.tv_sec - udpConnection->lastTime.tv_sec > timeout) {
            udpConnection->end_time = udpConnection->lastTime;
            getUdpInfo(udpConnection);
            int udpSd = udpConnection->getSocket();
            delete it->second;
            udpMap.erase(it++);
            close(udpSd);
        } else
            ++it;
    }
    pthread_cond_broadcast(&cond_udpmap);
    pthread_mutex_unlock(&mtx_udpmap);
    if (tcp) {
        pthread_mutex_lock(&mtx_tcpmap);
        for(auto it = tcpMap.begin(); it != tcpMap.end();) {
            TcpConnection *tcpConnection = it->second;
            /*if(tcpConnection->app.empty())
                tcpConnection->app = getApplication("tcp", tcpConnection->sourcePort,
                                                    tcpConnection->destIp, tcpConnection->destPort);*/
            clearTcpConnection(tcpConnection, true);
            delete it->second;
            tcpMap.erase(it++);
        }
        pthread_cond_broadcast(&cond_tcpmap);
        pthread_mutex_unlock(&mtx_tcpmap);
    }

}

void* pepaPing(void *p) {
    while(RUNNING) {
        sleep(1);
        timeval current_time{};
        gettimeofday(&current_time, nullptr);

        pthread_mutex_lock(&mtx_udpmap);
        for (auto it = udpMap.begin(); it != udpMap.end();) {
            UdpConnection *udpConnection = it->second;

            if (current_time.tv_sec > udpConnection->lastTime.tv_sec) {
                it++;
                continue;
            }
            std::ofstream myfile("report_udp_info.csv", std::ios_base::app);
            if (myfile.is_open()) {
                myfile << "udp," << udpConnection->key << ",";
                myfile << std::fixed << udpConnection->start_time.tv_sec << ","
                       << udpConnection->start_time.tv_usec << ",";
                myfile << std::fixed << 0 << "," << 0 << ",";
                myfile << udpConnection->tx_bytes << "," << udpConnection->rx_bytes << ",";
                myfile << udpConnection->app << "," << current_time.tv_sec << "," << current_time.tv_usec << "\n";
                myfile.close();
            }

            it++;
        }
        pthread_mutex_unlock(&mtx_udpmap);
        pthread_mutex_lock(&mtx_tcpmap);
        for (auto it = tcpMap.begin(); it != tcpMap.end();) {
            TcpConnection *tcpConnection = it->second;


            int tcpSd = tcpConnection->getSocket();
            struct tcp_info ti;
            socklen_t tisize = sizeof(ti);
            getsockopt(tcpSd, IPPROTO_TCP, TCP_INFO, &ti, &tisize);

            /* open a file and write results into it*/
            std::ofstream myfile("report_tcp_info.csv", std::ios_base::app);
            if (myfile.is_open()) {
                myfile << "tcp," << tcpConnection->key << ",";
                myfile << std::fixed << tcpConnection->start_time.tv_sec << ","
                       << tcpConnection->start_time.tv_usec << ",";
                myfile << std::fixed << 0 << "," << 0 << ",";
                myfile << tcpConnection->tx_bytes << "," << tcpConnection->rx_bytes << ",";
                myfile << ti.tcpi_min_rtt << "," << ti.tcpi_rtt << "," << ti.tcpi_rttvar << ",";
                myfile << ti.tcpi_lost << "," << ti.tcpi_snd_cwnd << "," << ti.tcpi_snd_mss << ","
                       << ti.tcpi_rcv_mss << ",";
                myfile << tcpConnection->app << "," << current_time.tv_sec << "," << current_time.tv_usec << "\n";

                myfile.close();
            }
            it++;

        }
        pthread_mutex_unlock(&mtx_tcpmap);
    }
    return nullptr;
}

void *epoll_events(void* p) {
    //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "thread epoll %d", syscall(__NR_gettid));

    struct epoll_event events[1000];
    pthread_attr_t tattr;
    int ret = pthread_attr_init(&tattr);
    ret = pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);

    while (RUNNING) {
        int n = epoll_wait(epollFd, events, 1000, 10000);
        if (n > 0) {
            int ret;

            pthread_t pid[n];
            for (int i = 0; i < n; i++) {
                struct epoll_event ev = events[i];
                if (ev.events & EPOLLOUT) {
                    ret = pthread_create(&pid[i], &tattr, t_sendPacket, ev.data.ptr);
                }
                if (ev.events & EPOLLIN)
                    if (ev.data.fd == vpnFd) {
                        lockMutexfd();
                        VPN_BYTES_AVIALABLE = true;
                        pthread_cond_broadcast(&cond_fd);
                        unlockMutexfd();
                    } else {
                        ret = pthread_create(&pid[i], &tattr, t_receivePacket, ev.data.ptr);
                    }
            }
        }
    }
    close(epollFd);
    return nullptr;
}

void startSniffer(int fd) {
    //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "thread main %d", syscall(__NR_gettid));
    if (first_execution){
        startmutex();
        pthread_mutex_init(&mtx_tcpmap,NULL);
        pthread_mutex_init(&mtx_udpmap,NULL);
        pthread_cond_init(&cond_tcpmap,NULL);
        pthread_cond_init(&cond_udpmap,NULL);
        pthread_cond_init(&cond_fd,NULL);
        first_execution = false;
    }else{
        for(std::vector< std::string *>::iterator it = keys.begin(); it != keys.end();) {
            std::string* connectionKey = *it;
            delete connectionKey;
            it = keys.erase(it);
        }
    }


    pthread_attr_t tattr;
    int ret = pthread_attr_init(&tattr);
    ret = pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);

    int count = 0;

    unsigned char packet[65536];
    int bytes_read;
    while(RUNNING) {
        while (count < 100) {
            lockMutexfd();
            if (!RUNNING) {
                unlockMutexfd();
                break;
            }

            //if (bytes_read <= 0) { 23 13 38 9.8
            //findUid();
            //clearSockets(false, 15);
            //}
            while ((bytes_read = read(fd, packet, 65536)) <= 0) {
                VPN_BYTES_AVIALABLE = false;
                pthread_cond_wait(&cond_fd, &mtx);

                if (!RUNNING) {
                    unlockMutexfd();
                    clearSockets(true, -1);
                    return;
                }
            }
            unlockMutexfd();
            epoll_ctl(epollFd, EPOLL_CTL_MOD, vpnFd, &fd_ev);

            //TODO: ipv6
            auto *ipHdr = (struct ip *) packet;
            uint16_t ipHdrLen = ipHdr->ip_hl * 4;
            uint16_t packetLen = ntohs(ipHdr->ip_len);

            std::string ipSrc = inet_ntoa(ipHdr->ip_src);
            std::string ipDst = inet_ntoa(ipHdr->ip_dst);

            /*
            char buffer [2*(bytes_read)+1];
            buffer[2*(bytes_read)] = 0;
            for(int j = 0; j < (bytes_read); j++)
                sprintf(&buffer[2*j], "%02X\n", packet[j]);

            __android_log_print(ANDROID_LOG_ERROR, "JNI ","TCP receiveData: %s\n", buffer);
            */

            // if UDP

            if (packet[9] == IPPROTO_UDP) {
                auto *udpHdr = (struct udphdr *) (packet + ipHdrLen);
                int udpHdrLen = udpHdr->uh_ulen * 4;
                ipSrc.append(",");
                ipSrc.append(to_string(ntohs(udpHdr->uh_sport)));
                ipDst.append(",");
                ipDst.append(to_string(ntohs(udpHdr->uh_dport)));

                std::string udpKey = ipSrc + "," + ipDst;
                pthread_mutex_lock(&mtx_udpmap);

                if (udpMap.count(udpKey) == 0) {
                    if (ntohl(ipHdr->ip_dst.s_addr) < 3758096384 ||
                        ntohl(ipHdr->ip_dst.s_addr) > 4026531839) {
                        int udpSd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
                        if (udpSd < 0){
                            pthread_mutex_unlock(&mtx_udpmap);
                            continue;
                        }

                        protect(udpSd);

                        struct sockaddr_in sin;
                        sin.sin_family = AF_INET;
                        sin.sin_addr.s_addr = ipHdr->ip_dst.s_addr;
                        sin.sin_port = udpHdr->uh_dport;

                        if (int res = connect(udpSd, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
                            close(udpSd);
                            pthread_mutex_unlock(&mtx_udpmap);
                            continue;
                        }

                        std::string app = getApplication("udp", ipHdr->ip_src, ntohs(udpHdr->uh_sport),
                                                         ipHdr->ip_dst, ntohs(udpHdr->uh_dport));

                        UdpConnection* udpConnection = new UdpConnection(udpKey, udpSd, packet,
                                                                         ipHdrLen, udpHdrLen, app);
                        udpConnection->sourcePort = ntohs(udpHdr->uh_sport);
                        udpConnection->destPort = ntohs(udpHdr->uh_dport);
                        udpMap.insert(std::make_pair(udpKey, udpConnection));
                        pthread_mutex_unlock(&mtx_udpmap);
                        udpConnection->ev.events =  EPOLLIN | EPOLLONESHOT;

                        std::string *connectionKey = new std::string(udpKey);
                        keys.push_back(connectionKey);
                        udpConnection->ev.data.ptr = connectionKey;

                        auto *newPacket = (uint8_t *) malloc(packetLen);
                        memcpy(newPacket, packet, packetLen);
                        udpConnection->queue.push(newPacket);
                        gettimeofday(&udpConnection->lastTime, nullptr);
                        gettimeofday(&udpConnection->start_time, nullptr);
                        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, udpSd, &udpConnection->ev) == -1) {
                            if (RUNNING)
                                exit(EXIT_FAILURE);
                            else{
                                broadcastUdp(udpConnection);
                                break;
                            }
                        }
                        broadcastUdp(udpConnection);

                        pthread_t pid;
                        pthread_create(&pid, &tattr, t_sendPacket, (void*) udpConnection->ev.data.ptr);;
                    } else{
                        pthread_mutex_unlock(&mtx_udpmap);
                    }
                } else {
                    UdpConnection *udpConnection = udpMap.at(udpKey);
                    bool exists = true;
                    while (udpConnection->busy) {
                        pthread_cond_wait(&cond_udpmap, &mtx_udpmap);
                        if (udpMap.count(udpKey) == 0) {
                            pthread_mutex_unlock(&mtx_udpmap);
                            exists = false;
                            break;
                        }
                    }
                    if (!exists)
                        continue;
                    udpConnection->busy = true;
                    pthread_mutex_unlock(&mtx_udpmap);

                    auto *newPacket = (uint8_t *) malloc(packetLen);
                    memcpy(newPacket, packet, packetLen);

                    udpConnection->queue.push(newPacket);
                    gettimeofday(&udpConnection->lastTime, nullptr);

                    broadcastUdp(udpConnection);
                    pthread_t pid;
                    pthread_create(&pid, &tattr, t_sendPacket, (void*) udpConnection->ev.data.ptr);
                }
            }
                // if TCP
            else if (packet[9] == IPPROTO_TCP) {
                auto *tcpHdr = (struct tcphdr *) (packet + ipHdrLen);
                uint16_t tcpHdrLen = tcpHdr->doff * 4;
                uint16_t payloadDataLen = packetLen - ipHdrLen - tcpHdrLen;

                ipSrc.append(",");
                ipSrc.append(to_string(ntohs(tcpHdr->source)));
                ipDst.append(",");
                ipDst.append(to_string(ntohs(tcpHdr->dest)));

                std::string tcpKey = ipSrc + "," + ipDst;
                //__android_log_print(ANDROID_LOG_ERROR, "JNI", "tcp 1:  %s ack:%d fin:%d phs:%d rst:%d syn:%d",tcpKey.c_str(), tcpHdr->ack,tcpHdr->fin,
                //                    tcpHdr->psh,tcpHdr->rst,tcpHdr->syn);
                pthread_mutex_lock(&mtx_tcpmap);
                if (tcpMap.count(tcpKey) == 0) {
                    //pthread_mutex_unlock(&mtx_tcpmap);
                    if (tcpHdr->syn && !tcpHdr->ack) {

                        int tcpSd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
                        if (tcpSd < 0){
                            pthread_mutex_unlock(&mtx_tcpmap);
                            continue;
                        }
                        protect(tcpSd);

                        struct sockaddr_in sin{};
                        sin.sin_family = AF_INET;
                        sin.sin_addr.s_addr = ipHdr->ip_dst.s_addr;
                        sin.sin_port = tcpHdr->dest;

                        if (int res = connect(tcpSd, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
                            if (errno != EINPROGRESS) {
                                close(tcpSd);
                                pthread_mutex_unlock(&mtx_tcpmap);
                                //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "closed %d", tcpSd);
                                continue;
                            }
                        }
                        std::string app = getApplication("tcp", ipHdr->ip_src, ntohs(tcpHdr->source),
                                                         ipHdr->ip_dst, ntohs(tcpHdr->dest));

                        TcpConnection *tcpConnection = new TcpConnection(tcpKey, tcpSd, packet,
                                                                         true, ipHdrLen, tcpHdrLen,
                                                                         payloadDataLen, app);
                        tcpConnection->receiveAck(vpnFd, TH_ACK | TH_SYN);

                        tcpConnection->ev.events = EPOLLOUT | EPOLLONESHOT;
                        std::string *connectionKey = new std::string(tcpKey);
                        keys.push_back(connectionKey);
                        tcpConnection->ev.data.ptr = connectionKey;

                        gettimeofday(&tcpConnection->start_time, nullptr);

                        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, tcpSd, &tcpConnection->ev) == -1){
                            __android_log_print(ANDROID_LOG_ERROR, "JNI", "error: %s with key %s", strerror(errno),((std::string *)(void *) tcpConnection->ev.data.ptr)->c_str());
                            if(RUNNING)
                                error("epoll_ctl: listen_sock");
                            else{
                                std::string keyConnection = clearTcpConnection(tcpConnection, false);
                                delete tcpConnection;
                                pthread_mutex_unlock(&mtx_tcpmap);
                                break;
                            }
                        }
                        tcpMap.insert(std::make_pair(tcpKey, tcpConnection));
                        tcpConnection->busy = false;
                        pthread_cond_broadcast(&cond_tcpmap);
                        pthread_mutex_unlock(&mtx_tcpmap);
                    }
                    else if (tcpHdr->fin) {
                        pthread_mutex_unlock(&mtx_tcpmap);
                        TcpConnection tcpConnection(tcpKey, NULL, packet, false, ipHdrLen,
                                                    tcpHdrLen, payloadDataLen, "");
                        tcpConnection.currAck++;
                        if (tcpHdr->ack)
                            tcpConnection.receiveAck(fd, TH_ACK);
                        else
                            tcpConnection.receiveAck(fd, TH_FIN | TH_ACK);
                    }
                    else if (tcpHdr->rst) {
                        pthread_mutex_unlock(&mtx_tcpmap);
                    }
                    else { // tcpHdr->ack
                        pthread_mutex_unlock(&mtx_tcpmap);
                        //__android_log_print(ANDROID_LOG_ERROR, "JNI", "else 1:  ack:%d fin:%d phs:%d rst:%d syn:%d",tcpHdr->ack,tcpHdr->fin,
                        //                    tcpHdr->psh,tcpHdr->rst,tcpHdr->syn);
                        TcpConnection tcpConnection(tcpKey, NULL, packet, false, ipHdrLen,
                                                    tcpHdrLen, payloadDataLen, "");
                        tcpConnection.currAck++;
                        tcpConnection.receiveAck(fd, TH_RST);
                    }
                } else {
                    TcpConnection *tcpConnection = tcpMap.at(tcpKey);

                    bool exists = true;
                    while (tcpConnection->busy) {
                        pthread_cond_wait(&cond_tcpmap, &mtx_tcpmap);
                        if (tcpMap.count(tcpKey) == 0) {
                            pthread_mutex_unlock(&mtx_tcpmap);
                            exists = false;
                            break;
                        }
                    }
                    if (!exists)
                        continue;
                    tcpConnection->busy = true;

                    pthread_mutex_unlock(&mtx_tcpmap);

                    if (tcpHdr->fin) {
                        tcpConnection->updateLastPacket(tcpHdr, payloadDataLen);

                        tcpConnection->currAck++;
                        tcpConnection->receiveAck(fd, TH_ACK | TH_FIN);

                        pthread_mutex_lock(&mtx_tcpmap);
                        std::string keyConnection = clearTcpConnection(tcpConnection, true);
                        delete tcpConnection;
                        tcpMap.erase(keyConnection);
                        pthread_cond_broadcast(&cond_tcpmap);
                        pthread_mutex_unlock(&mtx_tcpmap);
                    } else if (tcpHdr->rst) {
                        //tcpConnection->receiveAck(fd, TH_RST);

                        pthread_mutex_lock(&mtx_tcpmap);
                        std::string keyConnection = clearTcpConnection(tcpConnection, true);
                        delete tcpConnection;
                        tcpMap.erase(keyConnection);
                        pthread_cond_broadcast(&cond_tcpmap);
                        pthread_mutex_unlock(&mtx_tcpmap);
                    } else if (!tcpHdr->syn && tcpHdr->ack) {
                        if (payloadDataLen > 0) {
                            auto *newPacket = (uint8_t *) malloc(packetLen);
                            memcpy(newPacket, packet, packetLen);

                            tcpConnection->queue.push(newPacket);
                            if (tcpConnection->connected) {
                                pthread_t pid;
                                pthread_create(&pid, &tattr, t_sendPacket, (void*) tcpConnection->ev.data.ptr);;
                            }
                        } else {
                            tcpConnection->updateLastPacket(tcpHdr, payloadDataLen);
                        }
                        broadcastTcp(tcpConnection);

                    } else {
                        //__android_log_print(ANDROID_LOG_ERROR, "JNI ", "TCP ELSE");
                        broadcastTcp(tcpConnection);
                    }
                }
            }
            count++;
        }
        count = 0;
    }
    // Reset remaining TCP connections
    /*
    pthread_mutex_lock(&mtx_tcpmap);
    auto tcpIt = tcpMap.cbegin();
    while (tcpIt != tcpMap.cend()) {
        auto curr = tcpIt++;
        TcpConnection *tcpConnection = curr->second;
        tcpConnection->receiveAck(fd, TH_RST);
    }
    pthread_mutex_unlock(&mtx_tcpmap);
     */
    clearSockets(true, -1);
}

extern "C"{
JNIEXPORT jint JNICALL
Java_cl_niclabs_autovpn_AutoVpnService_startVPN(
        JNIEnv *env, jobject thiz, jint fd, jlong timestamp) {

    struct sigaction act, old_segv, old_bus, old_abrt;
    memset (&act, '\0', sizeof(act));
    act.sa_handler = &sig_handler;

    if (sigaction(SIGSEGV, &act, &old_segv) < 0)
        error("sigaction() failed installing SIGSEGV handler");
    if (sigaction(SIGBUS, &act, &old_bus) < 0)
        error("sigaction() failed installing SIGBUS handler");
    if (sigaction(SIGABRT, &act, &old_abrt) < 0)
        error("sigaction() failed installing SIGABRT handler");

    vpnFd = (int) fd;
    if (sigsetjmp(jbuf, 0) == 0) {
        RUNNING = true;
        env_timestamp = timestamp;
        jniEnv = env;
        jniEnv->GetJavaVM(&jvm);
        jObject = thiz;
        jclass clazz = env->GetObjectClass(thiz);
        protectMethod = env->GetMethodID(clazz, "protect", "(I)Z");
        packageNameMethod = env->GetMethodID(clazz, "getPackageName", "(I)Ljava/lang/String;");
        ownerApplicationMethod = env->GetMethodID(clazz, "getOwnerApplication",
                                                  "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;I)Ljava/lang/String;");

        jmethodID getFilesDir = env->GetMethodID(clazz, "getFilesDir", "()Ljava/io/File;");
        jobject dirobj = env->CallObjectMethod(thiz, getFilesDir);
        jclass dir = env->GetObjectClass(dirobj);
        jmethodID getStoragePath = env->GetMethodID(dir, "getAbsolutePath", "()Ljava/lang/String;");
        auto path = (jstring) env->CallObjectMethod(dirobj, getStoragePath);
        const char *pathstr = env->GetStringUTFChars(path, 0);
        chdir(pathstr);
        env->ReleaseStringUTFChars(path, pathstr);

        udpMap.clear();
        tcpMap.clear();
        packageMap.clear();

        epollFd = epoll_create( 0xD1E60 );
        if (epollFd < 0)
            exit(EXIT_FAILURE); // report error

        fd_ev.events =  EPOLLIN | EPOLLONESHOT;
        fd_ev.data.fd = vpnFd;

        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, vpnFd, &fd_ev) == -1) {
            exit(EXIT_FAILURE);
        }
        pthread_t pid;
        pthread_attr_t tattr;
        int ret = pthread_attr_init(&tattr);
        ret = pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
        pthread_create(&pid, &tattr, epoll_events, NULL);

        pthread_t pepaPid;
        pthread_create(&pepaPid, &tattr, pepaPing, NULL);

        startSniffer(vpnFd);
    } else
        RUNNING = false;

    if (sigaction(SIGSEGV, &old_segv, NULL) < 0)
        error("sigaction() failed restoring SIGSEGV handler");
    if (sigaction(SIGBUS, &old_bus, NULL) < 0)
        error("sigaction() failed restoring SIGBUS handler");
    if (sigaction(SIGABRT, &old_abrt, NULL) < 0)
        error("sigaction() failed restoring SIGABRT handler");

    return (jint) fd;
}
}

extern "C"{
JNIEXPORT jint JNICALL
Java_cl_niclabs_autovpn_AutoVpnService_endVPN(
        JNIEnv *env, jclass thiz) {
    lockMutexfd();
    RUNNING = false;
    close(vpnFd);
    pthread_cond_broadcast(&cond_fd);
    unlockMutexfd();

    return (jint) 1;
}
}
