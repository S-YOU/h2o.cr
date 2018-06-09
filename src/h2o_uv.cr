require "./h2o"
require "./lib_h2o/lib_h2o_uv"

class H2o
  alias Listener = (LibUv::UvStreamT*, LibC::Int) -> Void
  alias UvHandler = (LibUv::UvHandleT*) -> Void

  {% for method in %w(uv_loop_init uv_run uv_tcp_init uv_ip4_addr uv_tcp_bind uv_listen uv_accept uv_close uv_strerror) %}
  macro {{method.id}}(*args)
    LibUv.{{method.id}}(\{{*args}})
  end
  {% end %}
end
