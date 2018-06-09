require "h2o_evloop"


class H2oHello < H2o
  @config = LibH2o::H2oGlobalconfT.new
  @ctx = LibH2o::H2oContextT.new
  @accept_ctx = LibH2o::H2oAcceptCtxT.new
  @loop : LibH2o::H2oLoopT* = h2o_evloop_create()

  macro hello
    Handler.new do |handler, req|
      generator = uninitialized LibH2o::H2oGeneratorT[2]
      body = h2o_iovec_init("Hello, World!\n")
      req.value.res.status = 200
      req.value.res.reason = "OK"
      req.value.res.content_length = body.len
      # require h2o.c extension
      #h2o_add_header(req, H2O_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8")
      h2o_start_response(req, generator)
      h2o_send(req, pointerof(body), 1, LibH2o::H2oSendState::H2OSendStateFinal)
      0
    end
  end

  def on_accept(listener : LibH2o::H2oSocketT*, err : LibC::Char*) : Void
    return if err
    return unless s = h2o_evloop_socket_accept(listener)
    h2o_accept(pointerof(@accept_ctx), s)
  end

  def create_listener : Int32
    addr = uninitialized LibC::SockaddrIn
    reuseaddr_flag = 1

    pointerof(addr).clear
    addr.sin_family = LibC::AF_INET
    addr.sin_addr.s_addr = 0x100007f # b32(0x7f000001)
    addr.sin_port = 0xd21e           # b16(7890)

    if ((fd = socket(LibC::AF_INET, LibC::SOCK_STREAM, 0)) == -1 ||
       setsockopt(fd, LibC::SOL_SOCKET, LibC::SO_REUSEADDR, pointerof(reuseaddr_flag), 8) != 0 ||
       bind(fd, pointerof(addr).as(LibC::Sockaddr*), sizeof(LibC::SockaddrIn)) != 0 || listen(fd, SOMAXCONN) != 0)
      return -1
    end

    sock = h2o_evloop_socket_create(@ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ)
    h2o_socket_read_start(sock, LibH2o::H2oSocketCb.new { |listener, err|
      {{@type}}.instance.on_accept(listener, err)
    })
    0
  end

  def register_handler(hostconf : LibH2o::H2oHostconfT*, path : String, on_req : Handler) : LibH2o::H2oPathconfT*
    pathconf = h2o_config_register_path(hostconf, path, 0)
    handler = h2o_create_handler(pathconf, sizeof(LibH2o::H2oHandlerT))
    handler.value.on_req = on_req
    pathconf
  end

  def run : Void
    h2o_config_init(pointerof(@config))
    hostconf = h2o_config_register_host(pointerof(@config), h2o_iovec_init("default"), 65535)
    pathconf = register_handler(hostconf, "/hello", hello)

    h2o_context_init(pointerof(@ctx), @loop, pointerof(@config))

    @accept_ctx.ctx = pointerof(@ctx)
    @accept_ctx.hosts = @config.hosts

    if create_listener != 0
      return 1
    end

    while h2o_evloop_run(@ctx.loop, Int32::MAX) == 0; end
  end
end

fun main(argc : Int32, argv : UInt8**) : Int32
  H2oHello.run; 0
end

