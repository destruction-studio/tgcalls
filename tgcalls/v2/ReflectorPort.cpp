#include "v2/ReflectorPort.h"

#include <functional>
#include <memory>
#include <utility>
#include <vector>
#include <random>
#include <sstream>

#include "absl/algorithm/container.h"
#include "absl/strings/match.h"
#include "absl/types/optional.h"
#include "api/transport/stun.h"
#include "p2p/base/connection.h"
#include "p2p/base/p2p_constants.h"
#include "rtc_base/async_packet_socket.h"
#include "rtc_base/byte_order.h"
#include "rtc_base/checks.h"
#include "rtc_base/logging.h"
#include "rtc_base/net_helpers.h"
#include "rtc_base/socket_address.h"
#include "rtc_base/strings/string_builder.h"
#include "system_wrappers/include/field_trial.h"
#include "rtc_base/byte_order.h"

#include "RawTcpSocket.h"
#include "Instance.h" // tg-fork (Task 3096): kRelayLoginMarker.

#include "rtc_base/proxy_info.h"
#include "rtc_base/thread.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <thread>
#include <atomic>
#include <os/log.h>

static os_log_t tgai_voip_log() {
    static os_log_t log = os_log_create("com.destruction.tg.ai", "voip");
    return log;
}
#define TGAI_LOG(fmt, ...) os_log(tgai_voip_log(), fmt, ##__VA_ARGS__)
#define TGAI_ERR(fmt, ...) os_log_error(tgai_voip_log(), fmt, ##__VA_ARGS__)

namespace tgcalls {

namespace {

// rtc::Socket wrapper around a raw POSIX fd with poll thread for event signaling.
// Fires SignalConnectEvent/SignalReadEvent so AsyncTCPSocketBase (RawTcpSocket) works.
class RelayTunnelSocket : public rtc::Socket {
public:
    RelayTunnelSocket(int fd, const rtc::SocketAddress& remote_addr)
        : fd_(fd), remote_addr_(remote_addr), owner_thread_(rtc::Thread::Current()),
          alive_(std::make_shared<std::atomic<bool>>(true)) {
        poll_thread_ = std::thread(&RelayTunnelSocket::pollLoop, this);
    }

    ~RelayTunnelSocket() override {
        *alive_ = false;
        running_ = false;
        if (poll_thread_.joinable()) poll_thread_.join();
        if (fd_ >= 0) ::close(fd_);
    }

    rtc::SocketAddress GetLocalAddress() const override {
        sockaddr_in addr = {};
        socklen_t len = sizeof(addr);
        if (::getsockname(fd_, (sockaddr*)&addr, &len) == 0) {
            rtc::SocketAddress a; a.FromSockAddr(addr); return a;
        }
        return rtc::SocketAddress();
    }
    rtc::SocketAddress GetRemoteAddress() const override {
        return remote_addr_;
    }
    int Bind(const rtc::SocketAddress&) override { return 0; }
    int Connect(const rtc::SocketAddress&) override { return 0; }
    int Send(const void* pv, size_t cb) override {
        int r = ::send(fd_, pv, cb, 0);
        if (r < 0) {
            error_ = errno;
            TGAI_ERR("[TgAi/voip] relay Send failed: %{public}s", strerror(errno));
        }
        return r;
    }
    int SendTo(const void*, size_t, const rtc::SocketAddress&) override { return -1; }
    int Recv(void* pv, size_t cb, int64_t* ts) override {
        if (ts) *ts = -1;
        int r = ::recv(fd_, pv, cb, 0);
        if (r < 0) error_ = errno;
        return r;
    }
    int RecvFrom(void*, size_t, rtc::SocketAddress*, int64_t*) override { return -1; }
    int Listen(int) override { return -1; }
    rtc::Socket* Accept(rtc::SocketAddress*) override { return nullptr; }
    int Close() override {
        *alive_ = false;
        running_ = false;
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        return 0;
    }
    int GetError() const override { return error_; }
    void SetError(int e) override { error_ = e; }
    ConnState GetState() const override { return fd_ >= 0 ? CS_CONNECTED : CS_CLOSED; }
    int GetOption(Option, int*) override { return -1; }
    int SetOption(Option opt, int val) override {
        if (opt == OPT_NODELAY) return setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
        return -1;
    }

private:
    void pollLoop() {
        auto alive = alive_;

        usleep(10000);

        if (owner_thread_) {
            owner_thread_->PostTask([this, alive]() {
                if (*alive) {
                    SignalConnectEvent(this);
                }
            });
        }

        struct pollfd pfd;
        while (running_) {
            pfd = {fd_, POLLIN, 0};
            int ret = ::poll(&pfd, 1, 50);
            if (ret > 0) {
                if (pfd.revents & POLLIN) {
                    if (owner_thread_) {
                        owner_thread_->PostTask([this, alive]() {
                            if (*alive) SignalReadEvent(this);
                        });
                    }
                }
                if (pfd.revents & (POLLERR | POLLHUP)) {
                    if (owner_thread_) {
                        owner_thread_->PostTask([this, alive]() {
                            if (*alive) SignalCloseEvent(this, 0);
                        });
                    }
                    break;
                }
            }
        }
    }

    int fd_;
    rtc::SocketAddress remote_addr_;
    int error_ = 0;
    std::atomic<bool> running_{true};
    rtc::Thread* owner_thread_;
    std::thread poll_thread_;
    std::shared_ptr<std::atomic<bool>> alive_;
};

// Blocking connect to VoIP TCP-UDP relay. Returns connected fd or -1.
// Protocol: [1:userLen][user][1:passLen][pass][4:IP BE][2:port BE] -> [1:status]
static int relayConnectBlocking(const rtc::SocketAddress& relay_addr,
                                 const std::string& user, const std::string& pass,
                                 const rtc::SocketAddress& remote,
                                 int timeout_sec) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {timeout_sec, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(relay_addr.port());
    inet_pton(AF_INET, relay_addr.ipaddr().ToString().c_str(), &sa.sin_addr);

    if (::connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        TGAI_ERR("[TgAi/voip] relay TCP connect failed: %{public}s", strerror(errno));
        ::close(fd);
        return -1;
    }
    TGAI_LOG("[TgAi/voip] relay TCP connected");

    uint8_t buf[515];
    int p = 0;
    buf[p++] = (uint8_t)user.size();
    memcpy(buf + p, user.data(), user.size()); p += user.size();
    buf[p++] = (uint8_t)pass.size();
    memcpy(buf + p, pass.data(), pass.size()); p += pass.size();

    uint32_t ip = remote.ip();
    buf[p++] = (ip >> 24) & 0xFF; buf[p++] = (ip >> 16) & 0xFF;
    buf[p++] = (ip >> 8) & 0xFF;  buf[p++] = ip & 0xFF;
    uint16_t port = remote.port();
    buf[p++] = (port >> 8) & 0xFF; buf[p++] = port & 0xFF;

    TGAI_LOG("[TgAi/voip] relay handshake target=%d.%d.%d.%d:%d",
             (int)buf[p-6], (int)buf[p-5], (int)buf[p-4], (int)buf[p-3], port);

    if (::send(fd, buf, p, 0) != p) {
        TGAI_ERR("[TgAi/voip] relay handshake send failed");
        ::close(fd); return -1;
    }

    // 0x00=OK, 0x01=auth fail, 0x02=UDP fail
    uint8_t status;
    if (::recv(fd, &status, 1, MSG_WAITALL) != 1) {
        TGAI_ERR("[TgAi/voip] relay no response");
        ::close(fd); return -1;
    }
    if (status != 0x00) {
        TGAI_ERR("[TgAi/voip] relay rejected status=%d", (int)status);
        ::close(fd); return -1;
    }

    TGAI_LOG("[TgAi/voip] relay tunnel established to %{public}s", remote.ToString().c_str());

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

// tg-fork (Task 3096): blocking SOCKS5 CONNECT (RFC 1928/1929) through the
// user's genuine call-proxy. Vanilla never proxied the raw reflector leg (plain
// direct connect), but for our users direct reflector TCP is typically blocked
// (that's why they set a proxy in the first place), so honor the proxy for
// real. Returns connected pass-through fd (post-handshake) or -1.
static int socks5ConnectBlocking(const rtc::SocketAddress& proxy_addr,
                                 const std::string& user, const std::string& pass,
                                 const rtc::SocketAddress& remote,
                                 int timeout_sec) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = {timeout_sec, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int nodelay = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    struct sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(proxy_addr.port());
    if (inet_pton(AF_INET, proxy_addr.ipaddr().ToString().c_str(), &sa.sin_addr) != 1) {
        TGAI_LOG("[TgAi/voip] socks5: proxy address not an IPv4 literal: %{public}s", proxy_addr.ToString().c_str());
        ::close(fd); return -1;
    }
    if (::connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        TGAI_LOG("[TgAi/voip] socks5: TCP connect to proxy %{public}s failed: %{public}s", proxy_addr.ToString().c_str(), strerror(errno));
        ::close(fd); return -1;
    }

    const bool hasAuth = !user.empty() || !pass.empty();
    uint8_t greet[4];
    int gp = 0;
    greet[gp++] = 0x05;
    greet[gp++] = hasAuth ? 2 : 1;
    greet[gp++] = 0x00;                    // no-auth
    if (hasAuth) greet[gp++] = 0x02;       // username/password
    if (::send(fd, greet, gp, 0) != gp) {
        TGAI_LOG("[TgAi/voip] socks5: greeting send failed");
        ::close(fd); return -1;
    }
    uint8_t method[2];
    if (::recv(fd, method, 2, MSG_WAITALL) != 2 || method[0] != 0x05) {
        TGAI_LOG("[TgAi/voip] socks5: bad greeting response");
        ::close(fd); return -1;
    }
    if (method[1] == 0x02) {
        uint8_t auth[513];
        int ap = 0;
        auth[ap++] = 0x01;
        auth[ap++] = (uint8_t)user.size();
        memcpy(auth + ap, user.data(), user.size()); ap += user.size();
        auth[ap++] = (uint8_t)pass.size();
        memcpy(auth + ap, pass.data(), pass.size()); ap += pass.size();
        if (::send(fd, auth, ap, 0) != ap) {
            TGAI_LOG("[TgAi/voip] socks5: auth send failed");
            ::close(fd); return -1;
        }
        uint8_t authResp[2];
        if (::recv(fd, authResp, 2, MSG_WAITALL) != 2 || authResp[1] != 0x00) {
            TGAI_LOG("[TgAi/voip] socks5: auth rejected");
            ::close(fd); return -1;
        }
    } else if (method[1] != 0x00) {
        TGAI_LOG("[TgAi/voip] socks5: no acceptable auth method (0x%02x)", method[1]);
        ::close(fd); return -1;
    }

    uint8_t req[10];
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01; // CONNECT, IPv4
    uint32_t ip = remote.ip();
    req[4] = (ip >> 24) & 0xFF; req[5] = (ip >> 16) & 0xFF;
    req[6] = (ip >> 8) & 0xFF;  req[7] = ip & 0xFF;
    uint16_t port = remote.port();
    req[8] = (port >> 8) & 0xFF; req[9] = port & 0xFF;
    if (::send(fd, req, 10, 0) != 10) {
        TGAI_LOG("[TgAi/voip] socks5: CONNECT send failed");
        ::close(fd); return -1;
    }
    uint8_t rep[4];
    if (::recv(fd, rep, 4, MSG_WAITALL) != 4 || rep[1] != 0x00) {
        TGAI_LOG("[TgAi/voip] socks5: CONNECT rejected (rep=0x%02x)", (int)rep[1]);
        ::close(fd); return -1;
    }
    // Drain the bound-address tail of the reply.
    int tail;
    if (rep[3] == 0x01) tail = 4 + 2;
    else if (rep[3] == 0x04) tail = 16 + 2;
    else if (rep[3] == 0x03) {
        uint8_t dlen;
        if (::recv(fd, &dlen, 1, MSG_WAITALL) != 1) { ::close(fd); return -1; }
        tail = dlen + 2;
    } else { ::close(fd); return -1; }
    uint8_t skip[262];
    if (::recv(fd, skip, tail, MSG_WAITALL) != tail) {
        TGAI_LOG("[TgAi/voip] socks5: reply tail read failed");
        ::close(fd); return -1;
    }

    TGAI_LOG("[TgAi/voip] socks5: tunnel established via %{public}s to %{public}s",
             proxy_addr.ToString().c_str(), remote.ToString().c_str());

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

rtc::CopyOnWriteBuffer parseHex(std::string const &string) {
    rtc::CopyOnWriteBuffer result;
    
    for (size_t i = 0; i < string.length(); i += 2) {
        std::string byteString = string.substr(i, 2);
        char byte = (char)strtol(byteString.c_str(), NULL, 16);
        result.AppendData(&byte, 1);
    }
    
    return result;
}

int BindSocket(rtc::Socket* socket,
               const rtc::SocketAddress& local_address,
               uint16_t min_port,
               uint16_t max_port) {
    int ret = -1;
    if (min_port == 0 && max_port == 0) {
        // If there's no port range, let the OS pick a port for us.
        ret = socket->Bind(local_address);
    } else {
        // Otherwise, try to find a port in the provided range.
        for (int port = min_port; ret < 0 && port <= max_port; ++port) {
            ret = socket->Bind(rtc::SocketAddress(local_address.ipaddr(), port));
        }
    }
    return ret;
}

rtc::AsyncPacketSocket *CreateClientRawTcpSocket(
                                              rtc::SocketFactory *socket_factory_,
                                              const rtc::SocketAddress& local_address,
                                              const rtc::SocketAddress& remote_address,
                                              const rtc::ProxyInfo& proxy_info,
                                              const std::string& user_agent,
                                              const rtc::PacketSocketTcpOptions& tcp_options) {
    rtc::Socket* socket =
    socket_factory_->CreateSocket(local_address.family(), SOCK_STREAM);
    if (!socket) {
        return NULL;
    }
    
    if (BindSocket(socket, local_address, 0, 0) < 0) {
        // Allow BindSocket to fail if we're binding to the ANY address, since this
        // is mostly redundant in the first place. The socket will be bound when we
        // call Connect() instead.
        if (local_address.IsAnyIP()) {
            RTC_LOG(LS_WARNING) << "TCP bind failed with error " << socket->GetError()
            << "; ignoring since socket is using 'any' address.";
        } else {
            RTC_LOG(LS_ERROR) << "TCP bind failed with error " << socket->GetError();
            delete socket;
            return NULL;
        }
    }
    
    // Set TCP_NODELAY (via OPT_NODELAY) for improved performance; this causes
    // small media packets to be sent immediately rather than being buffered up,
    // reducing latency.
    //
    // Must be done before calling Connect, otherwise it may fail.
    if (socket->SetOption(rtc::Socket::OPT_NODELAY, 1) != 0) {
        RTC_LOG(LS_ERROR) << "Setting TCP_NODELAY option failed with error "
        << socket->GetError();
    }

    // tg-fork (Task 3096, mirror of desktop 3092): engage the TCP->UDP relay
    // tunnel ONLY for OUR relay endpoint, flagged by kRelayLoginMarker on the
    // SOCKS5 username. A user's genuine SOCKS5 call-proxy has no marker and
    // must fall through to the plain reflector connect below - vanilla never
    // proxied the raw reflector leg. Without this guard any user SOCKS5
    // call-proxy would get the relay handshake and break. Strip the marker
    // back to the uuid before relayConnectBlocking().
    const std::string relayMarker(kRelayLoginMarker);
    const bool hasSocks5 = (proxy_info.type == rtc::PROXY_SOCKS5) && !proxy_info.address.IsNil();
    const bool isOurRelay = hasSocks5 && (proxy_info.username.rfind(relayMarker, 0) == 0);
    if (isOurRelay) {
        const std::string uuid = proxy_info.username.substr(relayMarker.size());
        TGAI_LOG("[TgAi/voip] relay connecting via %{public}s to %{public}s",
                 proxy_info.address.ToString().c_str(), remote_address.ToString().c_str());

        delete socket;

        std::string pass_str;
        size_t passLen = proxy_info.password.GetLength();
        if (passLen > 0) {
            pass_str.resize(passLen);
            proxy_info.password.CopyTo(&pass_str[0], false);
        }

        int fd = relayConnectBlocking(proxy_info.address, uuid,
                                       pass_str, remote_address, 10);
        if (fd < 0) {
            return NULL;
        }

        rtc::Socket* tunnelSocket = new RelayTunnelSocket(fd, remote_address);
        return new rtc::RawTcpSocket(tunnelSocket);
    }

    if (hasSocks5) {
        // tg-fork (Task 3096): a user's genuine SOCKS5 call-proxy (no marker) -
        // tunnel the reflector leg through it with a real SOCKS5 CONNECT.
        TGAI_LOG("[TgAi/voip] socks5: user proxy %{public}s -> %{public}s",
                 proxy_info.address.ToString().c_str(), remote_address.ToString().c_str());

        delete socket;

        std::string pass_str;
        size_t passLen = proxy_info.password.GetLength();
        if (passLen > 0) {
            pass_str.resize(passLen);
            proxy_info.password.CopyTo(&pass_str[0], false);
        }

        int fd = socks5ConnectBlocking(proxy_info.address, proxy_info.username,
                                       pass_str, remote_address, 10);
        if (fd < 0) {
            TGAI_LOG("[TgAi/voip] socks5: proxy connect FAILED");
            return NULL;
        }

        rtc::Socket* tunnelSocket = new RelayTunnelSocket(fd, remote_address);
        return new rtc::RawTcpSocket(tunnelSocket);
    }

    if (socket->Connect(remote_address) < 0) {
        RTC_LOG(LS_ERROR) << "TCP connect failed with error " << socket->GetError();
        delete socket;
        return NULL;
    }

    // Finally, wrap that socket in a TCP or STUN TCP packet socket.
    rtc::AsyncPacketSocket* tcp_socket;
    tcp_socket = new rtc::RawTcpSocket(socket);

    return tcp_socket;
}

}

static int GetRelayPreference(cricket::ProtocolType proto) {
    switch (proto) {
        case cricket::PROTO_TCP:
            return cricket::ICE_TYPE_PREFERENCE_RELAY_TCP;
        case cricket::PROTO_TLS:
            return cricket::ICE_TYPE_PREFERENCE_RELAY_TLS;
        default:
            RTC_DCHECK(proto == cricket::PROTO_UDP);
            return cricket::ICE_TYPE_PREFERENCE_RELAY_UDP;
    }
}

ReflectorPort::ReflectorPort(const cricket::CreateRelayPortArgs& args,
                             rtc::SocketFactory *underlying_socket_factory,
                             rtc::AsyncPacketSocket* socket,
                             uint8_t serverId,
                             int server_priority,
                             bool standaloneReflectorMode,
                             uint32_t standaloneReflectorRoleId)
: Port(args.network_thread,
    cricket::RELAY_PORT_TYPE,
    args.socket_factory,
    args.network,
    args.username,
    args.password),
server_address_(*args.server_address),
credentials_(args.config->credentials),
socket_(socket),
underlying_socket_factory_(underlying_socket_factory),
error_(0),
stun_dscp_value_(rtc::DSCP_NO_CHANGE),
state_(STATE_CONNECTING),
server_priority_(server_priority),
standaloneReflectorMode_(standaloneReflectorMode),
standaloneReflectorRoleId_(standaloneReflectorRoleId) {
    serverId_ = serverId;
    
    if (standaloneReflectorMode_) {
        randomTag_ = standaloneReflectorRoleId_;
    } else {
        auto generator = std::mt19937(std::random_device()());
        auto distribution = std::uniform_int_distribution<uint32_t>();
        do {
            randomTag_ = distribution(generator);
        } while (!randomTag_);
    }
    
    auto rawPeerTag = parseHex(args.config->credentials.password);
    if (rawPeerTag.size() == 16) {
        peer_tag_.AppendData(rawPeerTag.data(), rawPeerTag.size() - 4);
    } else {
        for (int i = 0; i < 16; i++) {
            uint8_t zero = 0;
            peer_tag_.AppendData(&zero, 1);
        }
    }
    peer_tag_.AppendData((uint8_t *)&randomTag_, 4);
}

ReflectorPort::ReflectorPort(const cricket::CreateRelayPortArgs& args,
                             rtc::SocketFactory *underlying_socket_factory,
                             uint16_t min_port,
                             uint16_t max_port,
                             uint8_t serverId,
                             int server_priority,
                             bool standaloneReflectorMode,
                             uint32_t standaloneReflectorRoleId)
: Port(args.network_thread,
       cricket::RELAY_PORT_TYPE,
       args.socket_factory,
       args.network,
       min_port,
       max_port,
       args.username,
       args.password),
server_address_(*args.server_address),
credentials_(args.config->credentials),
socket_(NULL),
underlying_socket_factory_(underlying_socket_factory),
error_(0),
stun_dscp_value_(rtc::DSCP_NO_CHANGE),
state_(STATE_CONNECTING),
server_priority_(server_priority),
standaloneReflectorMode_(standaloneReflectorMode),
standaloneReflectorRoleId_(standaloneReflectorRoleId) {
    serverId_ = serverId;

    if (standaloneReflectorMode_) {
        randomTag_ = standaloneReflectorRoleId_;
    } else {
        auto generator = std::mt19937(std::random_device()());
        auto distribution = std::uniform_int_distribution<uint32_t>();
        do {
            randomTag_ = distribution(generator);
        } while (!randomTag_);
    }
    
    auto rawPeerTag = parseHex(args.config->credentials.password);
    if (rawPeerTag.size() == 16) {
        peer_tag_.AppendData(rawPeerTag.data(), rawPeerTag.size() - 4);
    } else {
        for (int i = 0; i < 16; i++) {
            uint8_t zero = 0;
            peer_tag_.AppendData(&zero, 1);
        }
    }
    peer_tag_.AppendData((uint8_t *)&randomTag_, 4);
}

ReflectorPort::~ReflectorPort() {
    // TODO(juberti): Should this even be necessary?

    // release the allocation by sending a refresh with
    // lifetime 0.
    if (ready()) {
        Release();
    }

    // TG-FIX: SIGSEGV-reflectorport-dtor — the unsubscribe used to run AFTER `delete socket_`,
    // calling into the freed socket's callback list (prod SIGSEGV x198). Unsubscribe first,
    // then delete; also guard against a null socket (GetLocalAddress already assumes it can be).
    if (socket_ != nullptr && server_address_.proto == cricket::PROTO_TCP) {
        socket_->UnsubscribeCloseEvent(this);
    }

    if (!SharedSocket()) {
        delete socket_;
    }
    socket_ = nullptr;
}

rtc::SocketAddress ReflectorPort::GetLocalAddress() const {
    return socket_ ? socket_->GetLocalAddress() : rtc::SocketAddress();
}

cricket::ProtocolType ReflectorPort::GetProtocol() const {
    return server_address_.proto;
}

void ReflectorPort::PrepareAddress() {
    if (peer_tag_.size() != 16) {
        RTC_LOG(LS_ERROR) << "Allocation can't be started without setting the"
        " peer tag.";
        OnAllocateError(cricket::STUN_ERROR_UNAUTHORIZED,
                        "Missing REFLECTOR server credentials.");
        return;
    }
    if (serverId_ == 0) {
        RTC_LOG(LS_ERROR) << "Allocation can't be started without setting the"
        " server id.";
        OnAllocateError(cricket::STUN_ERROR_UNAUTHORIZED,
                        "Missing REFLECTOR server id.");
        return;
    }

    if (!server_address_.address.port()) {
        // We will set default REFLECTOR port, if no port is set in the address.
        server_address_.address.SetPort(599);
    }

    if (!AllowedReflectorPort(server_address_.address.port())) {
        // This can only happen after a 300 ALTERNATE SERVER, since the port can't
        // be created with a disallowed port number.
        RTC_LOG(LS_ERROR) << "Attempt to start allocation with disallowed port# "
        << server_address_.address.port();
        OnAllocateError(cricket::STUN_ERROR_SERVER_ERROR,
                        "Attempt to start allocation to a disallowed port");
        return;
    }
    if (server_address_.address.IsUnresolvedIP()) {
        ResolveTurnAddress(server_address_.address);
    } else {
        // If protocol family of server address doesn't match with local, return.
        if (!IsCompatibleAddress(server_address_.address)) {
            RTC_LOG(LS_ERROR) << "IP address family does not match. server: "
            << server_address_.address.family()
            << " local: " << Network()->GetBestIP().family();
            OnAllocateError(cricket::STUN_ERROR_GLOBAL_FAILURE,
                            "IP address family does not match.");
            return;
        }

        // Insert the current address to prevent redirection pingpong.
        attempted_server_addresses_.insert(server_address_.address);

        RTC_LOG(LS_INFO) << ToString() << ": Trying to connect to REFLECTOR server via "
        << ProtoToString(server_address_.proto) << " @ "
        << server_address_.address.ToSensitiveString();
        if (!CreateReflectorClientSocket()) {
            RTC_LOG(LS_ERROR) << "Failed to create REFLECTOR client socket";
            OnAllocateError(cricket::SERVER_NOT_REACHABLE_ERROR,
                            "Failed to create REFLECTOR client socket.");
            return;
        }
        if (server_address_.proto == cricket::PROTO_UDP) {
            SendReflectorHello();
        }
    }
}

void ReflectorPort::SendReflectorHello() {
    if (!(state_ == STATE_CONNECTED || state_ == STATE_READY)) {
        return;
    }

    RTC_LOG(LS_WARNING)
    << ToString()
    << ": REFLECTOR sending ping to " << server_address_.address.ToString();

    if (server_address_.proto == cricket::PROTO_TCP) {
        rtc::ByteBufferWriter bufferWriter;
        bufferWriter.WriteBytes((const uint8_t *)peer_tag_.data(), peer_tag_.size());
        bufferWriter.WriteUInt32(0);
        
        while (bufferWriter.Length() % 4 != 0) {
            bufferWriter.WriteUInt8(0);
        }
        
        rtc::PacketOptions options;
        Send(bufferWriter.Data(), bufferWriter.Length(), options);
    } else {
        rtc::ByteBufferWriter bufferWriter;
        bufferWriter.WriteBytes((const uint8_t *)peer_tag_.data(), peer_tag_.size());
        for (int i = 0; i < 12; i++) {
            bufferWriter.WriteUInt8(0xffu);
        }
        bufferWriter.WriteUInt8(0xfeu);
        for (int i = 0; i < 3; i++) {
            bufferWriter.WriteUInt8(0xffu);
        }
        bufferWriter.WriteUInt64(123);
        
        while (bufferWriter.Length() % 4 != 0) {
            bufferWriter.WriteUInt8(0);
        }
        
        rtc::PacketOptions options;
        Send(bufferWriter.Data(), bufferWriter.Length(), options);
    }

    if (!is_running_ping_task_) {
        is_running_ping_task_ = true;

        int timeoutMs = 10000;
        // Send pings faster until response arrives
        if (state_ == STATE_CONNECTED) {
            timeoutMs = 500;
        }

        thread()->PostDelayedTask(SafeTask(task_safety_.flag(), [this] {
            is_running_ping_task_ = false;
            SendReflectorHello();
        }), webrtc::TimeDelta::Millis(timeoutMs));
    }
}

bool ReflectorPort::CreateReflectorClientSocket() {
    RTC_DCHECK(!socket_ || SharedSocket());

    if (server_address_.proto == cricket::PROTO_UDP && !SharedSocket()) {
        if (standaloneReflectorMode_ && Network()->name() == "shared-reflector-network") {
            const rtc::IPAddress ipv4_any_address(INADDR_ANY);
            socket_ = socket_factory()->CreateUdpSocket(rtc::SocketAddress(ipv4_any_address, 12345), min_port(), max_port());
        } else {
            socket_ = socket_factory()->CreateUdpSocket(rtc::SocketAddress(Network()->GetBestIP(), 0), min_port(), max_port());
        }
    } else if (server_address_.proto == cricket::PROTO_TCP) {
        RTC_DCHECK(!SharedSocket());
        int opts = 0;

        rtc::PacketSocketTcpOptions tcp_options;
        tcp_options.opts = opts;
        socket_ = CreateClientRawTcpSocket(
            underlying_socket_factory_,
            rtc::SocketAddress(Network()->GetBestIP(), 0), server_address_.address,
            proxy(), user_agent(), tcp_options);
    }

    if (!socket_) {
        error_ = SOCKET_ERROR;
        return false;
    }

    // Apply options if any.
    for (SocketOptionsMap::iterator iter = socket_options_.begin();
         iter != socket_options_.end(); ++iter) {
        socket_->SetOption(iter->first, iter->second);
    }

    if (!SharedSocket()) {
        // If socket is shared, AllocationSequence will receive the packet.
        socket_->RegisterReceivedPacketCallback([this](rtc::AsyncPacketSocket *socket, const rtc::ReceivedPacket &packet) {
            this->OnReadPacket(socket, packet);
        });
    }

    socket_->SignalReadyToSend.connect(this, &ReflectorPort::OnReadyToSend);

    socket_->SignalSentPacket.connect(this, &ReflectorPort::OnSentPacket);

    // TCP port is ready to send stun requests after the socket is connected,
    // while UDP port is ready to do so once the socket is created.
    if (server_address_.proto == cricket::PROTO_TCP ||
        server_address_.proto == cricket::PROTO_TLS) {
        socket_->SignalConnect.connect(this, &ReflectorPort::OnSocketConnect);
        socket_->SubscribeCloseEvent(this, [this](rtc::AsyncPacketSocket* socket, int error) { OnSocketClose(socket, error); });
    } else {
        state_ = STATE_CONNECTED;
    }
    return true;
}

void ReflectorPort::OnSocketConnect(rtc::AsyncPacketSocket* socket) {
    // This slot should only be invoked if we're using a connection-oriented
    // protocol.
    RTC_DCHECK(server_address_.proto == cricket::PROTO_TCP ||
               server_address_.proto == cricket::PROTO_TLS);

    // Do not use this port if the socket bound to an address not associated with
    // the desired network interface. This is seen in Chrome, where TCP sockets
    // cannot be given a binding address, and the platform is expected to pick
    // the correct local address.
    //
    // However, there are two situations in which we allow the bound address to
    // not be one of the addresses of the requested interface:
    // 1. The bound address is the loopback address. This happens when a proxy
    // forces TCP to bind to only the localhost address (see issue 3927).
    // 2. The bound address is the "any address". This happens when
    // multiple_routes is disabled (see issue 4780).
    //
    // Note that, aside from minor differences in log statements, this logic is
    // identical to that in TcpPort.
    const rtc::SocketAddress& socket_address = socket->GetLocalAddress();
    if (absl::c_none_of(Network()->GetIPs(),
                        [socket_address](const rtc::InterfaceAddress& addr) {
        return socket_address.ipaddr() == addr;
    })) {
        if (socket->GetLocalAddress().IsLoopbackIP()) {
            RTC_LOG(LS_WARNING) << "Socket is bound to the address:"
            << socket_address.ipaddr().ToSensitiveString()
            << ", rather than an address associated with network:"
            << Network()->ToString()
            << ". Still allowing it since it's localhost.";
        } else if (IPIsAny(Network()->GetBestIP())) {
            RTC_LOG(LS_WARNING)
            << "Socket is bound to the address:"
            << socket_address.ipaddr().ToSensitiveString()
            << ", rather than an address associated with network:"
            << Network()->ToString()
            << ". Still allowing it since it's the 'any' address"
            ", possibly caused by multiple_routes being disabled.";
        } else {
            RTC_LOG(LS_WARNING) << "Socket is bound to the address:"
            << socket_address.ipaddr().ToSensitiveString()
            << ", rather than an address associated with network:"
            << Network()->ToString() << ". Discarding REFLECTOR port.";
            OnAllocateError(
                            cricket::STUN_ERROR_GLOBAL_FAILURE,
                            "Address not associated with the desired network interface.");
            return;
        }
    }

    state_ = STATE_CONNECTED;  // It is ready to send stun requests.
    if (server_address_.address.IsUnresolvedIP()) {
        server_address_.address = socket_->GetRemoteAddress();
    }

    RTC_LOG(LS_INFO) << "ReflectorPort connected to "
    << socket->GetRemoteAddress().ToSensitiveString()
    << " using tcp.";

    if (server_address_.proto == cricket::PROTO_TCP && state_ != STATE_READY) {
        state_ = STATE_READY;

        RTC_LOG(LS_INFO)
        << ToString()
        << ": REFLECTOR " << server_address_.address.ToString() << " is now ready";
        
        const auto ipFormat = "reflector-" + std::to_string((uint32_t)serverId_) + "-" + std::to_string(randomTag_) + ".reflector";
        rtc::SocketAddress candidateAddress(ipFormat, server_address_.address.port());
        if (standaloneReflectorMode_) {
            candidateAddress.SetResolvedIP(server_address_.address.ipaddr());
        }
        
        // For relayed candidate, Base is the candidate itself.
        AddAddress(candidateAddress,          // Candidate address.
                   server_address_.address,          // Base address.
                   rtc::SocketAddress(),  // Related address.
                   cricket::UDP_PROTOCOL_NAME,
                   ProtoToString(server_address_.proto),  // The first hop protocol.
                   "",  // TCP canddiate type, empty for turn candidates.
                   cricket::RELAY_PORT_TYPE, GetRelayPreference(server_address_.proto),
                   server_priority_, ReconstructedServerUrl(false /* use_hostname */),
                   true);
        
        SendReflectorHello();
    }
}

void ReflectorPort::OnSocketClose(rtc::AsyncPacketSocket* socket, int error) {
    RTC_LOG(LS_WARNING) << ToString()
    << ": Connection with server failed with error: "
    << error;
    RTC_DCHECK(socket == socket_);
    //Close();
}

cricket::Connection* ReflectorPort::CreateConnection(const cricket::Candidate& remote_candidate,
                                                     CandidateOrigin origin) {
    // REFLECTOR-UDP can only connect to UDP candidates.
    if (!SupportsProtocol(remote_candidate.protocol())) {
        return nullptr;
    }

    auto remoteHostname = remote_candidate.address().hostname();
    if (remoteHostname.empty()) {
        return nullptr;
    }
    const auto ipFormat = "reflector-" + std::to_string((uint32_t)serverId_) + "-";
    if (!absl::StartsWith(remoteHostname, ipFormat) || !absl::EndsWith(remoteHostname, ".reflector")) {
        return nullptr;
    }
    if (remote_candidate.address().port() != server_address_.address.port()) {
        return nullptr;
    }

    if (state_ == STATE_DISCONNECTED || state_ == STATE_RECEIVEONLY) {
        return nullptr;
    }
    
    cricket::Candidate updated_remote_candidate = remote_candidate;
    if (server_address_.proto == cricket::PROTO_TCP) {
        rtc::SocketAddress updated_address = updated_remote_candidate.address();
        updated_address.SetResolvedIP(server_address_.address.ipaddr());
        updated_remote_candidate.set_address(updated_address);
    }

    cricket::ProxyConnection* conn = new cricket::ProxyConnection(NewWeakPtr(), 0, updated_remote_candidate);
    AddOrReplaceConnection(conn);

    return conn;
}

bool ReflectorPort::FailAndPruneConnection(const rtc::SocketAddress& address) {
    cricket::Connection* conn = GetConnection(address);
    if (conn != nullptr) {
        conn->FailAndPrune();
        return true;
    }
    return false;
}

int ReflectorPort::SetOption(rtc::Socket::Option opt, int value) {
    // Remember the last requested DSCP value, for STUN traffic.
    if (opt == rtc::Socket::OPT_DSCP)
        stun_dscp_value_ = static_cast<rtc::DiffServCodePoint>(value);

    if (!socket_) {
        // If socket is not created yet, these options will be applied during socket
        // creation.
        socket_options_[opt] = value;
        return 0;
    }
    return socket_->SetOption(opt, value);
}

int ReflectorPort::GetOption(rtc::Socket::Option opt, int* value) {
    if (!socket_) {
        SocketOptionsMap::const_iterator it = socket_options_.find(opt);
        if (it == socket_options_.end()) {
            return -1;
        }
        *value = it->second;
        return 0;
    }

    return socket_->GetOption(opt, value);
}

int ReflectorPort::GetError() {
    return error_;
}

int ReflectorPort::SendTo(const void* data,
                          size_t size,
                          const rtc::SocketAddress& addr,
                          const rtc::PacketOptions& options,
                          bool payload) {
    rtc::CopyOnWriteBuffer targetPeerTag;

    auto syntheticHostname = addr.hostname();

    uint32_t resolvedPeerTag = 0;
    auto resolvedPeerTagIt = resolved_peer_tags_by_hostname_.find(syntheticHostname);
    if (resolvedPeerTagIt != resolved_peer_tags_by_hostname_.end()) {
        resolvedPeerTag = resolvedPeerTagIt->second;
    } else {
        const auto prefixFormat = "reflector-" + std::to_string((uint32_t)serverId_) + "-";
        std::string suffixFormat = ".reflector";
        if (!absl::StartsWith(syntheticHostname, prefixFormat) || !absl::EndsWith(syntheticHostname, suffixFormat)) {
            RTC_LOG(LS_ERROR) << ToString()
            << ": Discarding SendTo request with destination "
            << addr.ToString();

            return -1;
        }

        auto startPosition = prefixFormat.size();
        auto tagString = syntheticHostname.substr(startPosition, syntheticHostname.size() - suffixFormat.size() - startPosition);

        std::stringstream tagStringStream(tagString);
        tagStringStream >> resolvedPeerTag;

        if (resolvedPeerTag == 0) {
            RTC_LOG(LS_ERROR) << ToString()
            << ": Discarding SendTo request with destination "
            << addr.ToString() << " (could not parse peer tag)";

            return -1;
        }

        resolved_peer_tags_by_hostname_.insert(std::make_pair(syntheticHostname, resolvedPeerTag));
    }
    
    targetPeerTag.AppendData(peer_tag_.data(), peer_tag_.size() - 4);
    targetPeerTag.AppendData((uint8_t *)&resolvedPeerTag, 4);
    
    rtc::ByteBufferWriter bufferWriter;
    bufferWriter.WriteBytes((const uint8_t *)targetPeerTag.data(), targetPeerTag.size());
    
    bufferWriter.WriteBytes((const uint8_t *)&randomTag_, 4);
    
    bufferWriter.WriteUInt32((uint32_t)size);
    bufferWriter.WriteBytes((const uint8_t *)data, size);
    
    while (bufferWriter.Length() % 4 != 0) {
        bufferWriter.WriteUInt8(0);
    }
    
    rtc::PacketOptions modified_options(options);
    CopyPortInformationToPacketInfo(&modified_options.info_signaled_after_sent);
    
    modified_options.info_signaled_after_sent.turn_overhead_bytes = bufferWriter.Length() - size;
    
    Send(bufferWriter.Data(), bufferWriter.Length(), modified_options);
    
    return static_cast<int>(size);
}

bool ReflectorPort::CanHandleIncomingPacketsFrom(
                                                 const rtc::SocketAddress& addr) const {
                                                     return server_address_.address == addr;
                                                 }

bool ReflectorPort::HandleIncomingPacket(rtc::AsyncPacketSocket* socket, rtc::ReceivedPacket const &packet) {
    if (socket != socket_) {
        // The packet was received on a shared socket after we've allocated a new
        // socket for this REFLECTOR port.
        return false;
    }
    
    uint8_t const *data = packet.payload().begin();
    size_t size = packet.payload().size();
    rtc::SocketAddress const &remote_addr = packet.source_address();
    auto packet_time_us = packet.arrival_time();
    
    // This is to guard against a STUN response from previous server after
    // alternative server redirection. TODO(guoweis): add a unit test for this
    // race condition.
    if (remote_addr != server_address_.address) {
        RTC_LOG(LS_WARNING) << ToString()
        << ": Discarding REFLECTOR message from unknown address: "
        << remote_addr.ToSensitiveString()
        << " server_address_: "
        << server_address_.address.ToSensitiveString();
        return false;
    }

    // The message must be at least 16 bytes (peer tag).
    if (size < 16) {
        RTC_LOG(LS_WARNING) << ToString()
        << ": Received REFLECTOR message that was too short (" << size << ")";
        return false;
    }

    if (state_ == STATE_DISCONNECTED) {
        RTC_LOG(LS_WARNING)
        << ToString()
        << ": Received REFLECTOR message while the REFLECTOR port is disconnected";
        return false;
    }

    uint8_t receivedPeerTag[16];
    memcpy(receivedPeerTag, data, 16);

    if (memcmp(receivedPeerTag, peer_tag_.data(), 16 - 4) != 0) {
        RTC_LOG(LS_WARNING)
        << ToString()
        << ": Received REFLECTOR message with incorrect peer_tag";
        return false;
    }

    if (state_ != STATE_READY) {
        state_ = STATE_READY;

        RTC_LOG(LS_INFO)
        << ToString()
        << ": REFLECTOR " << server_address_.address.ToString() << " is now ready";
        
        const auto ipFormat = "reflector-" + std::to_string((uint32_t)serverId_) + "-" + std::to_string(randomTag_) + ".reflector";
        rtc::SocketAddress candidateAddress(ipFormat, server_address_.address.port());
        if (standaloneReflectorMode_) {
            candidateAddress.SetResolvedIP(server_address_.address.ipaddr());
        }
        
        // For relayed candidate, Base is the candidate itself.
        AddAddress(candidateAddress,          // Candidate address.
                   server_address_.address,          // Base address.
                   rtc::SocketAddress(),  // Related address.
                   cricket::UDP_PROTOCOL_NAME,
                   ProtoToString(server_address_.proto),  // The first hop protocol.
                   "",  // TCP canddiate type, empty for turn candidates.
                   cricket::RELAY_PORT_TYPE, GetRelayPreference(server_address_.proto),
                   server_priority_, ReconstructedServerUrl(false /* use_hostname */),
                   true);
    }

    if (size > 16 + 4 + 4) {
        bool isSpecialPacket = false;
        if (size >= 16 + 12) {
            uint8_t specialTag[12];
            memcpy(specialTag, data + 16, 12);

            uint8_t expectedSpecialTag[12];
            memset(expectedSpecialTag, 0xff, 12);

            if (memcmp(specialTag, expectedSpecialTag, 12) == 0) {
                isSpecialPacket = true;
            }
        }

        if (!isSpecialPacket) {
            uint32_t senderTag = 0;
            memcpy(&senderTag, data + 16, 4);

            uint32_t dataSize = 0;
            memcpy(&dataSize, data + 16 + 4, 4);
            dataSize = be32toh(dataSize);
            if (dataSize > size - 16 - 4 - 4) {
                RTC_LOG(LS_WARNING)
                << ToString()
                << ": Received data packet with invalid size tag";
            } else {
                const auto ipFormat = "reflector-" + std::to_string((uint32_t)serverId_) + "-" + std::to_string(senderTag) + ".reflector";
                rtc::SocketAddress candidateAddress(ipFormat, server_address_.address.port());
                candidateAddress.SetResolvedIP(server_address_.address.ipaddr());
                
                int64_t packet_timestamp = -1;
                if (packet_time_us.has_value()) {
                    packet_timestamp = packet_time_us->us_or(-1);
                }
                DispatchPacket(rtc::ReceivedPacket::CreateFromLegacy(data + 16 + 4 + 4, dataSize, packet_timestamp, candidateAddress), cricket::ProtocolType::PROTO_UDP);
            }
        }
    }

    return true;
}

void ReflectorPort::OnReadPacket(rtc::AsyncPacketSocket* socket, rtc::ReceivedPacket const &packet) {
    HandleIncomingPacket(socket, packet);
}

void ReflectorPort::OnSentPacket(rtc::AsyncPacketSocket* socket,
                                 const rtc::SentPacket& sent_packet) {
    PortInterface::SignalSentPacket(sent_packet);
}

void ReflectorPort::OnReadyToSend(rtc::AsyncPacketSocket* socket) {
    if (ready()) {
        Port::OnReadyToSend();
    }
}

bool ReflectorPort::SupportsProtocol(absl::string_view protocol) const {
    // Turn port only connects to UDP candidates.
    return protocol == cricket::UDP_PROTOCOL_NAME;
}

void ReflectorPort::ResolveTurnAddress(const rtc::SocketAddress& address) {
    if (resolver_)
        return;

    RTC_LOG(LS_INFO) << ToString() << ": Starting TURN host lookup for "
    << address.ToSensitiveString();
    resolver_ = socket_factory()->CreateAsyncDnsResolver();
    resolver_->Start(address, [this] {
        // If DNS resolve is failed when trying to connect to the server using TCP,
        // one of the reason could be due to DNS queries blocked by firewall.
        // In such cases we will try to connect to the server with hostname,
        // assuming socket layer will resolve the hostname through a HTTP proxy (if
        // any).
        auto& result = resolver_->result();
        if (result.GetError() != 0 && (server_address_.proto == cricket::PROTO_TCP ||
                                       server_address_.proto == cricket::PROTO_TLS)) {
            if (!CreateReflectorClientSocket()) {
                OnAllocateError(cricket::SERVER_NOT_REACHABLE_ERROR,
                                "TURN host lookup received error.");
            }
            return;
        }

        // Copy the original server address in `resolved_address`. For TLS based
        // sockets we need hostname along with resolved address.
        rtc::SocketAddress resolved_address = server_address_.address;
        if (result.GetError() != 0 ||
            !result.GetResolvedAddress(Network()->GetBestIP().family(),
                                       &resolved_address)) {
            RTC_LOG(LS_WARNING) << ToString() << ": TURN host lookup received error "
            << result.GetError();
            error_ = result.GetError();
            OnAllocateError(cricket::SERVER_NOT_REACHABLE_ERROR,
                            "TURN host lookup received error.");
            return;
        }
        // Signal needs both resolved and unresolved address. After signal is sent
        // we can copy resolved address back into `server_address_`.
        SignalResolvedServerAddress(this, server_address_.address,
                                    resolved_address);
        server_address_.address = resolved_address;
        PrepareAddress();
    });
}

void ReflectorPort::OnSendStunPacket(const void* data,
                                     size_t size,
                                     cricket::StunRequest* request) {
    RTC_DCHECK(connected());
    rtc::PacketOptions options(StunDscpValue());
    options.info_signaled_after_sent.packet_type = rtc::PacketType::kTurnMessage;
    CopyPortInformationToPacketInfo(&options.info_signaled_after_sent);
    if (Send(data, size, options) < 0) {
        RTC_LOG(LS_ERROR) << ToString() << ": Failed to send TURN message, error: "
        << socket_->GetError();
    }
}

void ReflectorPort::OnAllocateError(int error_code, const std::string& reason) {
    // We will send SignalPortError asynchronously as this can be sent during
    // port initialization. This way it will not be blocking other port
    // creation.
    thread()->PostTask(
      SafeTask(task_safety_.flag(), [this] { SignalPortError(this); }));
    std::string address = GetLocalAddress().HostAsSensitiveURIString();
    int port = GetLocalAddress().port();
    if (server_address_.proto == cricket::PROTO_TCP &&
        server_address_.address.IsPrivateIP()) {
        address.clear();
        port = 0;
    }
    SignalCandidateError(this, cricket::IceCandidateErrorEvent(address, port, ReconstructedServerUrl(true /* use_hostname */), error_code, reason));
}

void ReflectorPort::Release() {
    state_ = STATE_RECEIVEONLY;
}

void ReflectorPort::Close() {
    if (!ready()) {
        OnAllocateError(cricket::SERVER_NOT_REACHABLE_ERROR, "");
    }
    // Stop the port from creating new connections.
    state_ = STATE_DISCONNECTED;
    // Delete all existing connections; stop sending data.
    for (auto kv : connections()) {
        kv.second->Destroy();
    }

    SignalReflectorPortClosed(this);
}

rtc::DiffServCodePoint ReflectorPort::StunDscpValue() const {
    return stun_dscp_value_;
}

// static
bool ReflectorPort::AllowedReflectorPort(int port) {
    return true;
}

void ReflectorPort::DispatchPacket(rtc::ReceivedPacket const &packet, cricket::ProtocolType proto) {
    if (cricket::Connection* conn = GetConnection(packet.source_address())) {
        conn->OnReadPacket(packet);
    } else {
        Port::OnReadPacket(packet, proto);
    }
}

int ReflectorPort::Send(const void* data,
                        size_t len,
                        const rtc::PacketOptions& options) {
    return socket_->SendTo(data, len, server_address_.address, options);
}

void ReflectorPort::HandleConnectionDestroyed(cricket::Connection* conn) {
}

std::string ReflectorPort::ReconstructedServerUrl(bool use_hostname) {
    // draft-petithuguenin-behave-turn-uris-01
    // turnURI       = scheme ":" turn-host [ ":" turn-port ]
    //                 [ "?transport=" transport ]
    // scheme        = "turn" / "turns"
    // transport     = "udp" / "tcp" / transport-ext
    // transport-ext = 1*unreserved
    // turn-host     = IP-literal / IPv4address / reg-name
    // turn-port     = *DIGIT
    std::string scheme = "turn";
    std::string transport = "tcp";
    switch (server_address_.proto) {
        case cricket::PROTO_SSLTCP:
        case cricket::PROTO_TLS:
            scheme = "turns";
            break;
        case cricket::PROTO_UDP:
            transport = "udp";
            break;
        case cricket::PROTO_TCP:
            break;
    }
    rtc::StringBuilder url;
    url << scheme << ":"
    << (use_hostname ? server_address_.address.hostname()
        : server_address_.address.ipaddr().ToString())
    << ":" << server_address_.address.port() << "?transport=" << transport;
    return url.Release();
}

}  // namespace cricket
