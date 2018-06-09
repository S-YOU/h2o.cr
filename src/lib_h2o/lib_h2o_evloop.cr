@[Link(ldflags: "-lh2o-evloop -lwslay")]
lib LibH2o
  fun h2o_evloop_create : H2oEvloopT*
  fun h2o_evloop_destroy(loop : H2oEvloopT*)
  fun h2o_evloop_get_execution_time : LibC::Int
  fun h2o_evloop_run(loop : H2oEvloopT*, max_wait : LibC::Int) : LibC::Int
  fun h2o_evloop_socket_create(loop : H2oLoopT*, fd : Int32, flags : Int32) : H2oSocketT*
  fun h2o_evloop_socket_accept(listener : H2oSocketT*) : H2oSocketT*
  fun h2o_now : UInt64

  struct StH2oEvloopT
    _pending_as_client : Void*
    _pending_as_server : Void*
    _statechanged : StH2oEvloopTStatechanged
    _now : UInt64
    _timeouts : H2oLinklistT
    exec_time_counter : StH2oSlidingCounterT
  end

  struct StH2oEvloopTStatechanged
    head : Void*
    tail_ref : Void**
  end

  struct StH2oTimeoutBackendPropertiesT
    _dummy : LibC::Char
  end

  alias H2oEvloopT = StH2oEvloopT
  alias H2oLoopT = H2oEvloopT
end
