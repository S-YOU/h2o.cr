require "./lib_h2o"
require "c/arpa/inet"

lib LibH2o
  $stderr : Void*
  $stdout : Void*

  $h2o__tokens_ptr : H2oTokenT*
end

module Constants
  H2O_TOKEN_CONTENT_TYPE = LibH2o.h2o__tokens_ptr + 23

  H2O_SOCKET_FLAG_DONT_READ             = 0x20
  H2O_DEFAULT_HANDSHAKE_TIMEOUT_IN_SECS =   10
  DEFAULT_TCP_FASTOPEN_QUEUE_LEN        = 4096

  SOMAXCONN = 128
end

class H2o
  include Constants

  NULL = nil

  alias Handler = (LibH2o::H2oHandlerT*, LibH2o::H2oReqT*) -> Int32

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

  {% for method in %w(malloc free) %}
  macro {{method.id}}(*args)
    LibC.{{method.id}}(\{{*args}})
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
