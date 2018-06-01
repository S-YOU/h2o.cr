lib LibH2o
  fun h2o_base64_encode_capacity : LibC::Int
  fun h2o_buffer_init(buffer : H2oBufferT**, prototype : H2oBufferPrototypeT*)
  fun h2o_buffer_link_to_pool(buffer : H2oBufferT*, pool : H2oMemPoolT*)
  fun h2o_buffer_set_prototype(buffer : H2oBufferT**, prototype : H2oBufferPrototypeT*)
  fun h2o_context_get_filter_context(ctx : H2oContextT*, filter : H2oFilterT*) : Void*
  fun h2o_context_get_handler_context(ctx : H2oContextT*, handler : H2oHandlerT*) : Void*
  fun h2o_context_get_logger_context(ctx : H2oContextT*, logger : H2oLoggerT*) : Void*
  fun h2o_context_get_storage(ctx : H2oContextT*, key : LibC::Int*, dispose_cb : (Void* -> Void)) : Void**
  fun h2o_context_set_filter_context(ctx : H2oContextT*, filter : H2oFilterT*, filter_ctx : Void*)
  fun h2o_context_set_handler_context(ctx : H2oContextT*, handler : H2oHandlerT*, handler_ctx : Void*)
  fun h2o_create_connection(sz : LibC::Int, ctx : H2oContextT*, hosts : H2oHostconfT**, connected_at : Timeval, callbacks : H2oConnCallbacksT*) : H2oConnT*
  fun h2o_doublebuffer_consume(db : H2oDoublebufferT*)
  fun h2o_doublebuffer_dispose(db : H2oDoublebufferT*)
  fun h2o_doublebuffer_init(db : H2oDoublebufferT*, prototype : H2oBufferPrototypeT*)
  fun h2o_doublebuffer_prepare(db : H2oDoublebufferT*, receiving : H2oBufferT**, max_bytes : LibC::Int) : H2oIovecT
  fun h2o_get_timestamp(ctx : H2oContextT*, pool : H2oMemPoolT*, ts : H2oTimestampT*) : Timeval*
  fun h2o_hostinfo_select_one(res : Addrinfo*) : Addrinfo*
  fun h2o_iovec_init(base : Void*, len : UInt64) : H2oIovecT
  fun h2o_lcstris(target : LibC::Char*, target_len : LibC::Int, test : LibC::Char*, test_len : LibC::Int) : LibC::Int
  fun h2o_linklist_init_anchor(anchor : H2oLinklistT*)
  fun h2o_linklist_insert(pos : H2oLinklistT*, node : H2oLinklistT*)
  fun h2o_linklist_insert_list(pos : H2oLinklistT*, list : H2oLinklistT*)
  fun h2o_linklist_is_empty(anchor : H2oLinklistT*) : LibC::Int
  fun h2o_linklist_is_linked(node : H2oLinklistT*) : LibC::Int
  fun h2o_linklist_unlink(node : H2oLinklistT*)
  fun h2o_mem_addref_shared(p : Void*)
  fun h2o_mem_alloc(sz : LibC::Int) : Void*
  fun h2o_mem_realloc(oldp : Void*, sz : LibC::Int) : Void*
  fun h2o_mem_release_shared(p : Void*) : LibC::Int
  fun h2o_mem_set_secure(b : Void*, c : LibC::Int, len : LibC::Int) : Void*
  fun h2o_memcpy(dst : Void*, src : Void*, n : LibC::Int) : Void*
  fun h2o_memrchr(s : Void*, c : LibC::Int, n : LibC::Int) : Void*
  fun h2o_proceed_response(req : H2oReqT*)
  fun h2o_pull(req : H2oReqT*, cb : H2oOstreamPullCb, buf : H2oIovecT*) : H2oSendStateT
  fun h2o_req_getenv(req : H2oReqT*, name : LibC::Char*, name_len : LibC::Int, allocate_if_not_found : LibC::Int) : H2oIovecT*
  fun h2o_req_unsetenv(req : H2oReqT*, name : LibC::Char*, name_len : LibC::Int)
  fun h2o_setup_next_ostream(req : H2oReqT*, slot : H2oOstreamT**)
  fun h2o_setup_next_prefilter(self : H2oReqPrefilterT*, req : H2oReqT*, slot : H2oOstreamT**)
  fun h2o_sliding_counter_is_running(counter : H2oSlidingCounterT*) : LibC::Int
  fun h2o_sliding_counter_start(counter : H2oSlidingCounterT*, now : Uint64T)
  fun h2o_socket_is_reading(sock : H2oSocketT*) : LibC::Int
  fun h2o_socket_is_writing(sock : H2oSocketT*) : LibC::Int
  fun h2o_socket_log_ssl_cipher(sock : H2oSocketT*, pool : H2oMemPoolT*) : H2oIovecT
  fun h2o_socket_log_ssl_protocol_version(sock : H2oSocketT*, pool : H2oMemPoolT*) : H2oIovecT
  fun h2o_socket_log_ssl_session_reused(sock : H2oSocketT*, pool : H2oMemPoolT*) : H2oIovecT
  fun h2o_socket_prepare_for_latency_optimized_write : LibC::Int
  fun h2o_socketpool_is_owned_socket(pool : H2oSocketpoolT*, sock : H2oSocketT*) : LibC::Int
  fun h2o_strtolower(s : LibC::Char*, len : LibC::Int)
  fun h2o_strtoupper(s : LibC::Char*, len : LibC::Int)
  fun h2o_timeout_is_linked(entry : H2oTimeoutEntryT*) : LibC::Int
  fun h2o_tolower(ch : LibC::Int) : LibC::Int
  fun h2o_toupper(ch : LibC::Int) : LibC::Int
  fun h2o_url_get_port(url : H2oUrlT*) : Uint16T
  fun h2o_url_init(url : H2oUrlT*, scheme : H2oUrlSchemeT*, authority : H2oIovecT, path : H2oIovecT) : LibC::Int
  fun h2o_url_stringify(pool : H2oMemPoolT*, url : H2oUrlT*) : H2oIovecT
  fun h2o_vector__erase(vector : H2oVectorT*, element_size : LibC::Int, index : LibC::Int)
  fun h2o_vector__reserve(pool : H2oMemPoolT*, vector : H2oVectorT*, element_size : LibC::Int, new_capacity : LibC::Int)
end

require "./lib_h2o_h2o.cr"
