require "h2o_uv"
require "crystal/patches"

class H2oHello < H2o
  @config = LibH2o::H2oGlobalconfT.new
  @ctx = LibH2o::H2oContextT.new
  @accept_ctx = LibH2o::H2oAcceptCtxT.new
  @uvloop = LibUv::UvLoopT.new

  macro hello
    Handler.new do |handler, req|
      generator = uninitialized LibH2o::H2oGeneratorT[2]
      body = h2o_iovec_init("Hello, World!\n")
      req.value.res.status = 200
      req.value.res.reason = "OK"
      req.value.res.content_length = body.len
      # require h2o.c extension
      h2o_add_header(req, H2O_TOKEN_CONTENT_TYPE, "text/plain; charset=utf-8")
      h2o_start_response(req, generator)
      h2o_send(req, pointerof(body), 1, LibH2o::H2oSendState::H2OSendStateFinal)
      0
    end
  end

  def on_accept(listener : LibH2o::UvStreamT*, status : Int32) : Void
    return if status != 0

    conn = LibC.malloc(sizeof(LibUv::UvTcpT)).as(LibUv::UvTcpS*)
    uv_tcp_init(listener.value.loop, conn)

    if uv_accept(listener, conn.as(LibH2o::UvStreamT*)) != 0
      return uv_close(conn.as(LibUv::UvHandleT*), UvHandler.new { |ptr| LibC.free(ptr) })
    end

    sock = h2o_uv_socket_create(conn.as(LibUv::UvStreamS*), UvHandler.new { |ptr| LibC.free(ptr) })
    h2o_accept(pointerof(@accept_ctx), sock)
  end

  def create_listener : Int32
    _listener = uninitialized LibUv::UvTcpT
    listener = pointerof(_listener)
    addr = uninitialized LibUv::SockaddrIn
    r = 0

    uv_tcp_init(@ctx.loop, listener)
    uv_ip4_addr("127.0.0.1", 7890, pointerof(addr))
    if (r = uv_tcp_bind(listener, pointerof(addr).as(LibUv::Sockaddr*), 0)) != 0
      uv_close(listener.as(LibUv::UvHandleT*), NULL)
    end
    if (r = uv_listen(listener.as(LibH2o::UvStreamT*), 128, Listener.new { |listener, status| {{@type}}.instance.on_accept(listener, status) })) != 0
      uv_close(listener.as(LibUv::UvHandleT*), NULL)
    end
    r
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

    uv_loop_init(pointerof(@uvloop))
    h2o_context_init(pointerof(@ctx), pointerof(@uvloop), pointerof(@config))

    @accept_ctx.ctx = pointerof(@ctx)
    @accept_ctx.hosts = @config.hosts

    if create_listener != 0
      return 1
    end

    uv_run(@ctx.loop, LibUv::UvRunMode::UvRunDefault)
  end
end

fun main(argc : Int32, argv : UInt8**) : Int32
  H2oHello.run; 0
end

