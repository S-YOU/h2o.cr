require "uv"

@[Link(ldflags: "-lh2o -lwslay")]
lib LibH2o
  alias H2oLoopT = LibUv::UvLoopT

  alias UvConnectS = LibUv::UvConnectS
  alias UvHandleS = LibUv::UvHandleS
  alias UvIoS = LibUv::UvIoS
  alias UvLoopS = LibUv::UvLoopS
  alias UvShutdownS = LibUv::UvShutdownS
  alias UvStreamS = LibUv::UvStreamS
  alias UvTimerS = LibUv::UvTimerS
  alias UvBufT = LibUv::UvBufT

  alias UvConnectT = UvConnectS
  alias UvHandleT = UvHandleS
  alias UvIoT = UvIoS
  alias UvLoopT = UvLoopS
  alias UvShutdownT = UvShutdownS
  alias UvStreamT = UvStreamS
  alias UvTimerT = UvTimerS

  alias UvAllocCb = (UvHandleT*, LibC::Int, UvBufT* -> Void)
  alias UvCloseCb = (UvHandleT* -> Void)
  alias UvConnectCb = (UvConnectT*, LibC::Int -> Void)
  alias UvConnectionCb = (UvStreamT*, LibC::Int -> Void)
  alias UvIoCb = (UvLoopS*, UvIoS*, LibC::UInt -> Void)
  alias UvReadCb = (UvStreamT*, SsizeT, UvBufT* -> Void)
  alias UvShutdownCb = (UvShutdownT*, LibC::Int -> Void)
  alias UvTimerCb = (UvTimerT* -> Void)

  enum UvHandleType
    UvUnknownHandle =  0
    UvAsync         =  1
    UvCheck         =  2
    UvFsEvent       =  3
    UvFsPoll        =  4
    UvHandle        =  5
    UvIdle          =  6
    UvNamedPipe     =  7
    UvPoll          =  8
    UvPrepare       =  9
    UvProcess       = 10
    UvStream        = 11
    UvTcp           = 12
    UvTimer         = 13
    UvTty           = 14
    UvUdp           = 15
    UvSignal        = 16
    UvFile          = 17
    UvHandleTypeMax = 18
  end
  enum UvReqType
    UvUnknownReq  =  0
    UvReq         =  1
    UvConnect     =  2
    UvWrite       =  3
    UvShutdown    =  4
    UvUdpSend     =  5
    UvFs          =  6
    UvWork        =  7
    UvGetaddrinfo =  8
    UvGetnameinfo =  9
    UvReqTypeMax  = 10
  end

  union UvHandleSU
    fd : LibC::Int
    reserved : Void*[4]
  end

  union UvStreamSU
    fd : LibC::Int
    reserved : Void*[4]
  end

  union UvTimerSU
    fd : LibC::Int
    reserved : Void*[4]
  end

  struct StH2oTimeoutBackendPropertiesT
    timer : UvTimerT
  end

  fun h2o_now(loop : UvLoopT*) : Uint64T
  fun h2o_uv_socket_create(stream : UvStreamT*, close_cb : UvCloseCb) : H2oSocketT*
end
