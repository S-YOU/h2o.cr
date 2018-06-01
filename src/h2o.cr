require "./lib_h2o"

lib LibH2o
  $stderr : Void*
  $stdout : Void*

  $h2o__tokens_ptr : H2oTokenT*
end

module Constants
  H2O_TOKEN_CONTENT_TYPE = LibH2o.h2o__tokens_ptr + 23
end

class H2o
  include Constants

  NULL = nil

  alias Handler = (LibH2o::H2oHandlerT*, LibH2o::H2oReqT*) -> Int32
  alias Listener = (LibUv::UvStreamT*, LibC::Int) -> Void
  alias UvHandler = (LibUv::UvHandleT*) -> Void

  macro h2o_iovec_init(base)
    LibH2o::H2oIovecT.new(base: {{base}}, len: {{base}}.size)
  end

  macro h2o_add_header(req, type, content)
    LibH2o.h2o_add_header({{req}}.offset_at(576).as(LibH2o::H2oMemPoolT*), {{req}}.offset_at(360).as(LibH2o::H2oHeadersT*), {{type}}, NULL, {{content}}, {{content}}.size)
  end

  {% for method in %w(h2o_send h2o_start_response h2o_add_header) %}
  macro {{method.id}}(*args)
    LibH2o.{{method.id}}(\{{*args}})
  end
  {% end %}

  {% for method in %w(uv_loop_init uv_run uv_tcp_init uv_ip4_addr uv_tcp_bind uv_listen uv_accept uv_close uv_strerror) %}
  macro {{method.id}}(*args)
    LibUv.{{method.id}}(\{{*args}})
  end
  {% end %}

  def self.run
    self.instance.run
  end

  macro inherited
    def self.instance
      @@instance ||= new
    end
  end

  private def initialize
  end

  forward_missing_to LibH2o
end
