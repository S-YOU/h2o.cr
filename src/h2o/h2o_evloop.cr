require "./h2o"
require "../lib_h2o/lib_h2o_evloop"

lib LibC
  TCP_DEFER_ACCEPT =  9
  TCP_QUICKACK     = 12
  TCP_FASTOPEN     = 23
  # SOMAXCONN        = 128
end

class H2o
  {% for method in %w(socket bind listen setsockopt strerror) %}
  macro {{method.id}}(*args)
    LibC.{{method.id}}(\{{*args}})
  end
  {% end %}

  {% for method in %w(h2o_evloop_create h2o_evloop_socket_create h2o_evloop_socket_accept h2o_accept h2o_socket_read_start h2o_evloop_run) %}
  macro {{method.id}}(*args)
    LibH2o.{{method.id}}(\{{*args}})
  end
  {% end %}
end
