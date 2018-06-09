require "./h2o"
require "./lib_h2o/lib_h2o_evloop"

class H2o
  {% for method in %w(socket bind listen setsockopt strerror) %}
  macro {{method.id}}(*args)
    LibC.{{method.id}}(\{{*args}})
  end
  {% end %}
end
