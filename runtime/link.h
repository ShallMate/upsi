#pragma once
#include "runtime/types.h"
#include <coproto/coproto.h>
#include <coproto/Socket/AsioSocket.h>
namespace upsi_runtime::link {
struct Stats { std::atomic<size_t> sent_bytes{0},recv_bytes{0}; };
class Context {
 public:
  Context(coproto::Socket socket,size_t rank): socket_(std::move(socket)), rank_(rank) {}
  size_t Rank() const { return rank_; }
  size_t NextRank() const { return 1-rank_; }
  size_t PrevRank() const { return NextRank(); }
  coproto::Socket& socket() { return socket_; }
  void SetRecvTimeout(uint64_t ms) { timeout_ms_=ms; }
  void Send(size_t peer,ByteContainerView v,std::string_view) {
    UPSI_ENFORCE(peer==NextRank());
    std::vector<uint8_t> copy(v.size());
    if(v.size()) std::memcpy(copy.data(),v.data(),v.size());
    coproto::sync_wait(socket_.send(std::move(copy)));
  }
  void SendAsync(size_t peer,ByteContainerView v,std::string_view tag) { Send(peer,v,tag); }
  Buffer Recv(size_t peer,std::string_view) {
    UPSI_ENFORCE(peer==NextRank()); std::vector<uint8_t> data;
    macoro::stop_source stop;
    auto timer=std::make_shared<boost::asio::steady_timer>(coproto::global_io_context());
    timer->expires_after(std::chrono::milliseconds(timeout_ms_));
    timer->async_wait([stop](const boost::system::error_code& ec) mutable { if(!ec) stop.request_stop(); });
    try { coproto::sync_wait(socket_.recvResize(data, stop.get_token())); }
    catch (...) { timer->cancel(); throw; }
    timer->cancel(); return Buffer(std::move(data));
  }
  std::shared_ptr<Stats> GetStats() {
    stats_->sent_bytes=socket_.bytesSent(); stats_->recv_bytes=socket_.bytesReceived(); return stats_;
  }
 private:
  coproto::Socket socket_; size_t rank_; uint64_t timeout_ms_=600000;
  std::shared_ptr<Stats> stats_=std::make_shared<Stats>();
};
inline std::vector<std::shared_ptr<Context>> SetupTcpWorld(size_t n) {
  UPSI_ENFORCE(n==2);
  auto pair=coproto::AsioSocket::makePair();
  return {std::make_shared<Context>(std::move(pair[0]),0),std::make_shared<Context>(std::move(pair[1]),1)};
}
}
