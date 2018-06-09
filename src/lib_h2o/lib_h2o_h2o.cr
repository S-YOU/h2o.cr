lib LibH2o
  $h2o__num_tokens : UInt64
  $h2o__tokens : H2oTokenT[100]
  $h2o_alpn_protocols : H2oIovecT*
  $h2o_connection_id : Uint64T
  $h2o_file_default_index_files : LibC::Char**
  $h2o_hostinfo_max_threads : LibC::Int
  $h2o_http1client_error_is_eos : LibC::Char*
  $h2o_http2_alpn_protocols : H2oIovecT*
  $h2o_http2_npn_protocols : LibC::Char*
  $h2o_mem__set_secure : (Void*, LibC::Int, LibC::Int -> Void*)
  $h2o_mime_attributes_as_is : H2oMimeAttributesT
  $h2o_npn_protocols : LibC::Char*
  $h2o_socket_buffer_mmap_settings : H2oBufferMmapSettingsT
  $h2o_socket_buffer_prototype : H2oBufferPrototypeT
  $h2o_socket_error_closed : LibC::Char*
  $h2o_socket_error_conn_fail : LibC::Char*
  $h2o_socket_error_io : LibC::Char*
  $h2o_socket_error_out_of_memory : LibC::Char*
  $h2o_socket_error_ssl_cert_invalid : LibC::Char*
  $h2o_socket_error_ssl_cert_name_mismatch : LibC::Char*
  $h2o_socket_error_ssl_decode : LibC::Char*
  $h2o_socket_error_ssl_no_cert : LibC::Char*
  $h2o_url_host_to_sun_err_is_not_unix_socket : LibC::Char*
  alias FinalStatusHandlerCb = (Void*, H2oGlobalconfT*, H2oReqT* -> H2oIovecT)
  alias H2oCacheHashcodeT = Uint32T
  alias H2oHostinfoGetaddrCb = (H2oHostinfoGetaddrReqT, LibC::Char*, Addrinfo*, Void* -> Void)
  alias H2oHttp1clientBodyCb = (H2oHttp1clientT*, LibC::Char* -> LibC::Int)
  alias H2oHttp1clientConnectCb = (H2oHttp1clientT*, LibC::Char*, H2oIovecT**, LibC::Int*, LibC::Int* -> H2oHttp1clientHeadCb)
  alias H2oHttp1clientHeadCb = (H2oHttp1clientT*, LibC::Char*, LibC::Int, LibC::Int, H2oIovecT, StH2oHeaderT*, LibC::Int, LibC::Int -> H2oHttp1clientBodyCb)
  alias H2oHttp1clientInformationalCb = (H2oHttp1clientT*, LibC::Int, LibC::Int, H2oIovecT, StH2oHeaderT*, LibC::Int -> LibC::Int)

  alias H2oMemcachedGetCb = (H2oIovecT, Void* -> Void)
  alias H2oMultithreadReceiverCb = (H2oMultithreadReceiverT*, H2oLinklistT* -> Void)
  alias H2oMultithreadResponseCb = (H2oMultithreadRequestT* -> Void)
  alias H2oOstreamPullCb = (H2oGeneratorT*, H2oReqT*, H2oIovecT* -> H2oSendStateT)
  alias H2oSocketCb = (H2oSocketT*, LibC::Char* -> Void)
  alias H2oSocketSslResumptionGetAsyncCb = (H2oSocketT*, H2oIovecT -> Void)
  alias H2oSocketSslResumptionNewCb = (H2oIovecT, H2oIovecT -> Void)
  alias H2oSocketpoolConnectCb = (H2oSocketT*, LibC::Char*, Void* -> Void)
  alias H2oTimeoutCb = (H2oTimeoutEntryT* -> Void)
  alias InAddrT = Uint32T
  alias Int32T = X__Int32T
  alias Int64T = X__Int64T
  alias PthreadT = LibC::ULong
  alias SaFamilyT = LibC::UShort
  alias SocklenT = X__SocklenT
  alias SsizeT = X__SsizeT
  alias StH2oAccessLogFilehandleT = Void
  alias StH2oCacheT = Void
  alias StH2oConfiguratorCommandT = Void
  alias StH2oConfiguratorT = Void
  alias StH2oFastcgiHandlerT = Void
  alias StH2oFileHandlerT = Void
  alias StH2oFilecacheT = Void
  alias StH2oHostinfoGetaddrReqT = Void
  alias StH2oLogconfT = Void
  alias StH2oMemcachedContextT = Void
  alias StH2oMemcachedReqT = Void
  alias StH2oMimemapT = Void
  alias StH2oMultithreadQueueT = Void
  alias StH2oRedirectHandlerT = Void
  alias StH2oReproxyHandlerT = Void
  alias StH2oSocketpoolConnectRequestT = Void
  alias StPtlsContextT = Void
  alias TimeT = X__TimeT
  alias Uint16T = X__Uint16T
  alias Uint32T = X__Uint32T
  alias Uint64T = X__Uint64T
  alias Uint8T = X__Uint8T

  alias X_IoLockT = Void
  alias X__Int32T = LibC::Int
  alias X__Int64T = LibC::Long
  alias X__Off64T = LibC::Long
  alias X__OffT = LibC::Long
  alias X__SocklenT = LibC::UInt
  alias X__SsizeT = LibC::Long
  alias X__SusecondsT = LibC::Long
  alias X__TimeT = LibC::Long
  alias X__Uint16T = LibC::UShort
  alias X__Uint32T = LibC::UInt
  alias X__Uint64T = LibC::ULong
  alias X__Uint8T = UInt8
  enum EnH2oSocketpoolTypeT
    H2OSocketpoolTypeNamed    = 0
    H2OSocketpoolTypeSockaddr = 1
  end
  enum H2oMimemapType
    H2OMimemapTypeMimetype = 0
    H2OMimemapTypeDynamic  = 1
  end
  enum H2oSendState
    H2OSendStateInProgress = 0
    H2OSendStateFinal      = 1
    H2OSendStateError      = 2
  end

  fun h2o__fatal(msg : LibC::Char*)
  fun h2o__hostinfo_getaddr_dispatch(req : H2oHostinfoGetaddrReqT)
  fun h2o__lcstris_core(target : LibC::Char*, test : LibC::Char*, test_len : LibC::Int) : LibC::Int
  fun h2o__proxy_process_request(req : H2oReqT*)
  fun h2o_accept(ctx : H2oAcceptCtxT*, sock : H2oSocketT*)
  fun h2o_accept_setup_async_ssl_resumption(ctx : H2oMemcachedContextT, expiration : LibC::UInt)
  fun h2o_access_log_open_handle(path : LibC::Char*, fmt : LibC::Char*, escape : LibC::Int) : H2oAccessLogFilehandleT
  fun h2o_access_log_open_log(path : LibC::Char*) : LibC::Int
  fun h2o_access_log_register(pathconf : H2oPathconfT*, handle : H2oAccessLogFilehandleT) : H2oLoggerT*
  fun h2o_access_log_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_add_header(pool : H2oMemPoolT*, headers : H2oHeadersT*, token : StH2oTokenT*, orig_name : Void*, value : LibC::Char*, value_len : LibC::Int)
  fun h2o_add_header_by_str(pool : H2oMemPoolT*, headers : H2oHeadersT*, name : LibC::Char*, name_len : LibC::Int, maybe_token : LibC::Int, orig_name : LibC::Char*, value : LibC::Char*, value_len : LibC::Int)
  fun h2o_add_ostream(req : H2oReqT*, sz : LibC::Int, slot : H2oOstreamT**) : H2oOstreamT*
  fun h2o_add_prefilter(req : H2oReqT*, sz : LibC::Int) : H2oReqPrefilterT*
  fun h2o_append_to_null_terminated_list(list : Void***, element : Void*)
  fun h2o_barrier_done(barrier : H2oBarrierT*) : LibC::Int
  fun h2o_barrier_init(barrier : H2oBarrierT*, count : LibC::Int)
  fun h2o_barrier_wait(barrier : H2oBarrierT*) : LibC::Int
  fun h2o_base64_encode : LibC::Int
  fun h2o_buffer__dispose_linked(p : Void*)
  fun h2o_buffer__do_free(buffer : H2oBufferT*)
  fun h2o_buffer_consume(inbuf : H2oBufferT**, delta : LibC::Int)
  fun h2o_buffer_dispose(_buffer : H2oBufferT**)
  fun h2o_buffer_dispose(buffer : H2oBufferT**)
  fun h2o_buffer_reserve(inbuf : H2oBufferT**, min_guarantee : LibC::Int) : H2oIovecT
  fun h2o_build_destination(req : H2oReqT*, prefix : LibC::Char*, prefix_len : LibC::Int, use_path_normalized : LibC::Int) : H2oIovecT
  fun h2o_cache_calchash(s : LibC::Char*, len : LibC::Int) : H2oCacheHashcodeT
  fun h2o_cache_clear(cache : H2oCacheT)
  fun h2o_cache_create(flags : LibC::Int, capacity : LibC::Int, duration : Uint64T, destroy_cb : (H2oIovecT -> Void)) : H2oCacheT
  fun h2o_cache_delete(cache : H2oCacheT, now : Uint64T, key : H2oIovecT, keyhash : H2oCacheHashcodeT)
  fun h2o_cache_destroy(cache : H2oCacheT)
  fun h2o_cache_fetch(cache : H2oCacheT, now : Uint64T, key : H2oIovecT, keyhash : H2oCacheHashcodeT) : H2oCacheRefT*
  fun h2o_cache_get_capacity : LibC::Int
  fun h2o_cache_get_duration(cache : H2oCacheT) : Uint64T
  fun h2o_cache_release(cache : H2oCacheT, ref : H2oCacheRefT*)
  fun h2o_cache_set(cache : H2oCacheT, now : Uint64T, key : H2oIovecT, keyhash : H2oCacheHashcodeT, value : H2oIovecT) : LibC::Int
  fun h2o_chunked_register(pathconf : H2oPathconfT*)
  fun h2o_compress_brotli_open(pool : H2oMemPoolT*, quality : LibC::Int, estimated_cotent_length : LibC::Int) : H2oCompressContextT*
  fun h2o_compress_gunzip_open(pool : H2oMemPoolT*) : H2oCompressContextT*
  fun h2o_compress_gzip_open(pool : H2oMemPoolT*, quality : LibC::Int) : H2oCompressContextT*
  fun h2o_compress_register(pathconf : H2oPathconfT*, args : H2oCompressArgsT*)
  fun h2o_compress_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_concat_list(pool : H2oMemPoolT*, list : H2oIovecT*, count : LibC::Int) : H2oIovecT
  fun h2o_config_create_envconf(src : H2oEnvconfT*) : H2oEnvconfT*
  fun h2o_config_dispose(config : H2oGlobalconfT*)
  fun h2o_config_dispose_pathconf(pathconf : H2oPathconfT*)
  fun h2o_config_init(config : H2oGlobalconfT*)
  fun h2o_config_init_pathconf(pathconf : H2oPathconfT*, globalconf : H2oGlobalconfT*, path : LibC::Char*, mimemap : H2oMimemapT)
  fun h2o_config_register_host(config : H2oGlobalconfT*, host : H2oIovecT, port : Uint16T) : H2oHostconfT*
  fun h2o_config_register_path(hostconf : H2oHostconfT*, path : LibC::Char*, flags : LibC::Int) : H2oPathconfT*
  fun h2o_config_register_simple_status_handler(config : H2oGlobalconfT*, name : H2oIovecT, status_handler : FinalStatusHandlerCb)
  fun h2o_config_register_status_handler(config : H2oGlobalconfT*, x1 : H2oStatusHandlerT)
  fun h2o_config_setenv(envconf : H2oEnvconfT*, name : LibC::Char*, value : LibC::Char*)
  fun h2o_config_unsetenv(envconf : H2oEnvconfT*, name : LibC::Char*)
  fun h2o_contains_token(haysack : LibC::Char*, haysack_len : LibC::Int, needle : LibC::Char*, needle_len : LibC::Int, separator : LibC::Int) : LibC::Int
  fun h2o_context_dispose(context : H2oContextT*)
  fun h2o_context_dispose_pathconf_context(ctx : H2oContextT*, pathconf : H2oPathconfT*)
  fun h2o_context_init(context : H2oContextT*, loop : H2oLoopT*, config : H2oGlobalconfT*)
  fun h2o_context_init_pathconf_context(ctx : H2oContextT*, pathconf : H2oPathconfT*)
  fun h2o_context_request_shutdown(context : H2oContextT*)
  fun h2o_context_set_logger_context(ctx : H2oContextT*, logger : H2oLoggerT*, logger_ctx : Void*)
  fun h2o_context_update_timestamp_cache(ctx : H2oContextT*)
  fun h2o_create_filter(conf : H2oPathconfT*, sz : LibC::Int) : H2oFilterT*
  fun h2o_create_handler(conf : H2oPathconfT*, sz : LibC::Int) : H2oHandlerT*
  fun h2o_create_logger(conf : H2oPathconfT*, sz : LibC::Int) : H2oLoggerT*
  fun h2o_decode_base64url(pool : H2oMemPoolT*, src : LibC::Char*, len : LibC::Int) : H2oIovecT
  fun h2o_delegate_request(req : H2oReqT*, current_handler : H2oHandlerT*)
  fun h2o_delegate_request_deferred(req : H2oReqT*, current_handler : H2oHandlerT*)
  fun h2o_delete_header(headers : H2oHeadersT*, cursor : SsizeT) : SsizeT
  fun h2o_dispose_request(req : H2oReqT*)
  fun h2o_dump_memory(fp : File*, buf : LibC::Char*, len : LibC::Int)
  fun h2o_duration_stats_register(conf : H2oGlobalconfT*)
  fun h2o_errordoc_register(pathconf : H2oPathconfT*, errdocs : H2oErrordocT*, cnt : LibC::Int)
  fun h2o_errordoc_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_expires_register(pathconf : H2oPathconfT*, args : H2oExpiresArgsT*)
  fun h2o_expires_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_extract_push_path_from_link_header(pool : H2oMemPoolT*, value : LibC::Char*, value_len : LibC::Int, base_path : H2oIovecT, input_scheme : H2oUrlSchemeT*, input_authority : H2oIovecT, base_scheme : H2oUrlSchemeT*, base_authority : H2oIovecT*, filtered_value : H2oIovecT*) : H2oIovecVectorT
  fun h2o_fastcgi_register_by_address(pathconf : H2oPathconfT*, sa : Sockaddr*, salen : SocklenT, vars : H2oFastcgiConfigVarsT*) : H2oFastcgiHandlerT
  fun h2o_fastcgi_register_by_hostport(pathconf : H2oPathconfT*, host : LibC::Char*, port : Uint16T, vars : H2oFastcgiConfigVarsT*) : H2oFastcgiHandlerT
  fun h2o_fastcgi_register_by_spawnproc(pathconf : H2oPathconfT*, argv : LibC::Char**, vars : H2oFastcgiConfigVarsT*) : H2oFastcgiHandlerT
  fun h2o_fastcgi_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_file_get_mimemap(handler : H2oFileHandlerT) : H2oMimemapT
  fun h2o_file_register(pathconf : H2oPathconfT*, real_path : LibC::Char*, index_files : LibC::Char**, mimemap : H2oMimemapT, flags : LibC::Int) : H2oFileHandlerT
  fun h2o_file_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_file_register_file(pathconf : H2oPathconfT*, real_path : LibC::Char*, mime_type : H2oMimemapTypeT*, flags : LibC::Int) : H2oHandlerT*
  fun h2o_file_send(req : H2oReqT*, status : LibC::Int, reason : LibC::Char*, path : LibC::Char*, mime_type : H2oIovecT, flags : LibC::Int) : LibC::Int
  fun h2o_filecache_clear(cache : H2oFilecacheT)
  fun h2o_filecache_close_file(ref : H2oFilecacheRefT*)
  fun h2o_filecache_create(capacity : LibC::Int) : H2oFilecacheT
  fun h2o_filecache_destroy(cache : H2oFilecacheT)
  fun h2o_filecache_get_etag : LibC::Int
  fun h2o_filecache_get_last_modified(ref : H2oFilecacheRefT*, outbuf : LibC::Char*) : Tm*
  fun h2o_filecache_open_file(cache : H2oFilecacheT, path : LibC::Char*, oflag : LibC::Int) : H2oFilecacheRefT*
  fun h2o_find_header(headers : H2oHeadersT*, token : H2oTokenT*, cursor : SsizeT) : SsizeT
  fun h2o_find_header_by_str(headers : H2oHeadersT*, name : LibC::Char*, name_len : LibC::Int, cursor : SsizeT) : SsizeT
  fun h2o_get_compressible_types(headers : H2oHeadersT*) : LibC::Int
  fun h2o_get_filext(path : LibC::Char*, len : LibC::Int) : H2oIovecT
  fun h2o_get_redirect_method(method : H2oIovecT, status : LibC::Int) : H2oIovecT
  fun h2o_headers_append_command(cmds : H2oHeadersCommandT**, cmd : LibC::Int, name : H2oIovecT*, value : H2oIovecT)
  fun h2o_headers_is_prohibited_name(token : H2oTokenT*) : LibC::Int
  fun h2o_headers_register(pathconf : H2oPathconfT*, cmds : H2oHeadersCommandT*)
  fun h2o_headers_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_hex_decode(dst : Void*, src : LibC::Char*, src_len : LibC::Int) : LibC::Int
  fun h2o_hex_encode(dst : LibC::Char*, src : Void*, src_len : LibC::Int)
  fun h2o_hostinfo_aton(host : H2oIovecT, addr : InAddr*) : LibC::Int
  fun h2o_hostinfo_getaddr(receiver : H2oMultithreadReceiverT*, name : H2oIovecT, serv : H2oIovecT, family : LibC::Int, socktype : LibC::Int, protocol : LibC::Int, flags : LibC::Int, cb : H2oHostinfoGetaddrCb, cbdata : Void*) : H2oHostinfoGetaddrReqT
  fun h2o_hostinfo_getaddr_cancel(req : H2oHostinfoGetaddrReqT)
  fun h2o_hostinfo_getaddr_receiver(receiver : H2oMultithreadReceiverT*, messages : H2oLinklistT*)
  fun h2o_htmlescape(pool : H2oMemPoolT*, src : LibC::Char*, len : LibC::Int) : H2oIovecT
  fun h2o_http1client_cancel(client : H2oHttp1clientT*)
  fun h2o_http1client_connect(client : H2oHttp1clientT**, data : Void*, ctx : H2oHttp1clientCtxT*, host : H2oIovecT, port : Uint16T, is_ssl : LibC::Int, cb : H2oHttp1clientConnectCb)
  fun h2o_http1client_connect_with_pool(client : H2oHttp1clientT**, data : Void*, ctx : H2oHttp1clientCtxT*, sockpool : H2oSocketpoolT*, cb : H2oHttp1clientConnectCb)
  fun h2o_http1client_steal_socket(client : H2oHttp1clientT*) : H2oSocketT*
  fun h2o_http2_debug_state_register(hostconf : H2oHostconfT*, hpack_enabled : LibC::Int)
  fun h2o_http2_debug_state_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_init_request(req : H2oReqT*, conn : H2oConnT*, src : H2oReqT*)
  fun h2o_iovec_is_token(buf : H2oIovecT*) : LibC::Int
  fun h2o_log_request(logconf : H2oLogconfT, req : H2oReqT*, len : LibC::Int*, buf : LibC::Char*) : LibC::Char*
  fun h2o_logconf_compile(fmt : LibC::Char*, escape : LibC::Int, errbuf : LibC::Char*) : H2oLogconfT
  fun h2o_logconf_dispose(logconf : H2oLogconfT)
  fun h2o_lookup_token(name : LibC::Char*, len : LibC::Int) : H2oTokenT*
  fun h2o_mem_alloc_pool(pool : H2oMemPoolT*, sz : LibC::Int) : Void*
  fun h2o_mem_alloc_recycle(allocator : H2oMemRecycleT*, sz : LibC::Int) : Void*
  fun h2o_mem_alloc_shared(pool : H2oMemPoolT*, sz : LibC::Int, dispose : (Void* -> Void)) : Void*
  fun h2o_mem_clear_pool(pool : H2oMemPoolT*)
  fun h2o_mem_free_recycle(allocator : H2oMemRecycleT*, p : Void*)
  fun h2o_mem_init_pool(pool : H2oMemPoolT*)
  fun h2o_mem_link_shared(pool : H2oMemPoolT*, p : Void*)
  fun h2o_mem_swap(x : Void*, y : Void*, len : LibC::Int)
  fun h2o_memcached_cancel_get(ctx : H2oMemcachedContextT, req : H2oMemcachedReqT)
  fun h2o_memcached_create_context(host : LibC::Char*, port : Uint16T, text_protocol : LibC::Int, num_threads : LibC::Int, prefix : LibC::Char*) : H2oMemcachedContextT
  fun h2o_memcached_delete(ctx : H2oMemcachedContextT, key : H2oIovecT, flags : LibC::Int)
  fun h2o_memcached_get(ctx : H2oMemcachedContextT, receiver : H2oMultithreadReceiverT*, key : H2oIovecT, cb : H2oMemcachedGetCb, cb_data : Void*, flags : LibC::Int) : H2oMemcachedReqT
  fun h2o_memcached_receiver(receiver : H2oMultithreadReceiverT*, messages : H2oLinklistT*)
  fun h2o_memcached_set(ctx : H2oMemcachedContextT, key : H2oIovecT, value : H2oIovecT, expiration : Uint32T, flags : LibC::Int)
  fun h2o_memis(_target : Void*, target_len : LibC::Int, _test : Void*, test_len : LibC::Int) : LibC::Int
  fun h2o_memis(target : Void*, target_len : LibC::Int, test : Void*, test_len : LibC::Int) : LibC::Int
  fun h2o_mimemap_clear_types(mimemap : H2oMimemapT)
  fun h2o_mimemap_clone(src : H2oMimemapT) : H2oMimemapT
  fun h2o_mimemap_create : H2oMimemapT
  fun h2o_mimemap_define_dynamic(mimemap : H2oMimemapT, exts : LibC::Char**, globalconf : H2oGlobalconfT*) : H2oMimemapTypeT*
  fun h2o_mimemap_define_mimetype(mimemap : H2oMimemapT, ext : LibC::Char*, mime : LibC::Char*, attr : H2oMimeAttributesT*)
  fun h2o_mimemap_get_default_attributes(mime : LibC::Char*, attr : H2oMimeAttributesT*)
  fun h2o_mimemap_get_default_type(mimemap : H2oMimemapT) : H2oMimemapTypeT*
  fun h2o_mimemap_get_type_by_extension(mimemap : H2oMimemapT, ext : H2oIovecT) : H2oMimemapTypeT*
  fun h2o_mimemap_get_type_by_mimetype(mimemap : H2oMimemapT, mime : H2oIovecT, exact_match_only : LibC::Int) : H2oMimemapTypeT*
  fun h2o_mimemap_has_dynamic_type(mimemap : H2oMimemapT) : LibC::Int
  fun h2o_mimemap_on_context_dispose(mimemap : H2oMimemapT, ctx : H2oContextT*)
  fun h2o_mimemap_on_context_init(mimemap : H2oMimemapT, ctx : H2oContextT*)
  fun h2o_mimemap_remove_type(mimemap : H2oMimemapT, ext : LibC::Char*)
  fun h2o_mimemap_set_default_type(mimemap : H2oMimemapT, mime : LibC::Char*, attr : H2oMimeAttributesT*)
  fun h2o_multithread_create_queue(loop : H2oLoopT*) : H2oMultithreadQueueT
  fun h2o_multithread_create_thread(tid : PthreadT*, attr : PthreadAttrT*, func : (Void* -> Void*), arg : Void*)
  fun h2o_multithread_destroy_queue(queue : H2oMultithreadQueueT)
  fun h2o_multithread_register_receiver(queue : H2oMultithreadQueueT, receiver : H2oMultithreadReceiverT*, cb : H2oMultithreadReceiverCb)
  fun h2o_multithread_send_message(receiver : H2oMultithreadReceiverT*, message : H2oMultithreadMessageT*)
  fun h2o_multithread_send_request(receiver : H2oMultithreadReceiverT*, req : H2oMultithreadRequestT*)
  fun h2o_multithread_unregister_receiver(queue : H2oMultithreadQueueT, receiver : H2oMultithreadReceiverT*)
  fun h2o_next_token(iter : H2oIovecT*, separator : LibC::Int, element_len : LibC::Int*, value : H2oIovecT*) : LibC::Char*
  fun h2o_ostream_send_next(ostream : H2oOstreamT*, req : H2oReqT*, bufs : H2oIovecT*, bufcnt : LibC::Int, state : H2oSendStateT)
  fun h2o_process_request(req : H2oReqT*)
  fun h2o_proxy_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_proxy_register_reverse_proxy(pathconf : H2oPathconfT*, upstream : H2oUrlT*, config : H2oProxyConfigVarsT*)
  fun h2o_push_path_in_link_header(req : H2oReqT*, value : LibC::Char*, value_len : LibC::Int) : H2oIovecT
  fun h2o_redirect_register(pathconf : H2oPathconfT*, internal : LibC::Int, status : LibC::Int, prefix : LibC::Char*) : H2oRedirectHandlerT
  fun h2o_redirect_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_reprocess_request(req : H2oReqT*, method : H2oIovecT, scheme : H2oUrlSchemeT*, authority : H2oIovecT, path : H2oIovecT, overrides : H2oReqOverridesT*, is_delegated : LibC::Int)
  fun h2o_reprocess_request_deferred(req : H2oReqT*, method : H2oIovecT, scheme : H2oUrlSchemeT*, authority : H2oIovecT, path : H2oIovecT, overrides : H2oReqOverridesT*, is_delegated : LibC::Int)
  fun h2o_reproxy_register(pathconf : H2oPathconfT*)
  fun h2o_reproxy_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_req_bind_conf(req : H2oReqT*, hostconf : H2oHostconfT*, pathconf : H2oPathconfT*)
  fun h2o_req_fill_mime_attributes(req : H2oReqT*)
  fun h2o_req_log_error(req : H2oReqT*, module : LibC::Char*, fmt : LibC::Char*, ...)
  fun h2o_rewrite_headers(pool : H2oMemPoolT*, headers : H2oHeadersT*, cmd : H2oHeadersCommandT*)
  fun h2o_sem_destroy(sem : H2oSemT*)
  fun h2o_sem_init(sem : H2oSemT*, capacity : SsizeT)
  fun h2o_sem_post(sem : H2oSemT*)
  fun h2o_sem_set_capacity(sem : H2oSemT*, new_capacity : SsizeT)
  fun h2o_sem_wait(sem : H2oSemT*)
  fun h2o_send(req : H2oReqT*, bufs : H2oIovecT*, bufcnt : LibC::Int, state : H2oSendStateT)
  fun h2o_send_error_400(req : H2oReqT*, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_403(req : H2oReqT*, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_404(req : H2oReqT*, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_405(req : H2oReqT*, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_416(req : H2oReqT*, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_417(req : H2oReqT*, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_500(req : H2oReqT*, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_502(req : H2oReqT*, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_503(req : H2oReqT*, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_deferred(req : H2oReqT*, status : LibC::Int, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_error_generic(req : H2oReqT*, status : LibC::Int, reason : LibC::Char*, body : LibC::Char*, flags : LibC::Int)
  fun h2o_send_inline(req : H2oReqT*, body : LibC::Char*, len : LibC::Int)
  fun h2o_send_redirect(req : H2oReqT*, status : LibC::Int, reason : LibC::Char*, url : LibC::Char*, url_len : LibC::Int)
  fun h2o_send_redirect_internal(req : H2oReqT*, method : H2oIovecT, url_str : LibC::Char*, url_len : LibC::Int, preserve_overrides : LibC::Int)
  fun h2o_send_state_is_in_progress(s : H2oSendStateT) : LibC::Int
  fun h2o_set_header(pool : H2oMemPoolT*, headers : H2oHeadersT*, token : H2oTokenT*, value : LibC::Char*, value_len : LibC::Int, overwrite_if_exists : LibC::Int)
  fun h2o_set_header_by_str(pool : H2oMemPoolT*, headers : H2oHeadersT*, name : LibC::Char*, name_len : LibC::Int, maybe_token : LibC::Int, value : LibC::Char*, value_len : LibC::Int, overwrite_if_exists : LibC::Int)
  fun h2o_set_header_token(pool : H2oMemPoolT*, headers : H2oHeadersT*, token : H2oTokenT*, value : LibC::Char*, value_len : LibC::Int)
  fun h2o_sliding_counter_stop(counter : H2oSlidingCounterT*, now : Uint64T)
  fun h2o_socket__write_on_complete(sock : H2oSocketT*, status : LibC::Int)
  fun h2o_socket__write_pending(sock : H2oSocketT*)
  fun h2o_socket_close(sock : H2oSocketT*)
  fun h2o_socket_compare_address(x : Sockaddr*, y : Sockaddr*) : LibC::Int
  fun h2o_socket_connect(loop : H2oLoopT*, addr : Sockaddr*, addrlen : SocklenT, cb : H2oSocketCb) : H2oSocketT*
  fun h2o_socket_dispose_export(info : H2oSocketExportT*)
  fun h2o_socket_do_prepare_for_latency_optimized_write : LibC::Int
  fun h2o_socket_dont_read(sock : H2oSocketT*, dont_read : LibC::Int)
  fun h2o_socket_export(sock : H2oSocketT*, info : H2oSocketExportT*) : LibC::Int
  fun h2o_socket_get_fd(sock : H2oSocketT*) : LibC::Int
  fun h2o_socket_get_loop(sock : H2oSocketT*) : H2oLoopT*
  fun h2o_socket_get_ssl_cipher(sock : H2oSocketT*) : LibC::Char*
  fun h2o_socket_get_ssl_cipher_bits(sock : H2oSocketT*) : LibC::Int
  fun h2o_socket_get_ssl_protocol_version(sock : H2oSocketT*) : LibC::Char*
  fun h2o_socket_get_ssl_session_id(sock : H2oSocketT*) : H2oIovecT
  fun h2o_socket_get_ssl_session_reused(sock : H2oSocketT*) : LibC::Int
  fun h2o_socket_getnumerichost : LibC::Int
  fun h2o_socket_getpeername(sock : H2oSocketT*, sa : Sockaddr*) : SocklenT
  fun h2o_socket_getport(sa : Sockaddr*) : Int32T
  fun h2o_socket_getsockname(sock : H2oSocketT*, sa : Sockaddr*) : SocklenT
  fun h2o_socket_import(loop : H2oLoopT*, info : H2oSocketExportT*) : H2oSocketT*
  fun h2o_socket_log_ssl_cipher_bits(sock : H2oSocketT*, pool : H2oMemPoolT*) : H2oIovecT
  fun h2o_socket_log_ssl_session_id(sock : H2oSocketT*, pool : H2oMemPoolT*) : H2oIovecT
  fun h2o_socket_notify_write(sock : H2oSocketT*, cb : H2oSocketCb)
  fun h2o_socket_read_start(sock : H2oSocketT*, cb : H2oSocketCb)
  fun h2o_socket_read_stop(sock : H2oSocketT*)
  fun h2o_socket_setpeername(sock : H2oSocketT*, sa : Sockaddr*, len : SocklenT)
  fun h2o_socket_ssl_async_resumption_init(get_cb : H2oSocketSslResumptionGetAsyncCb, new_cb : H2oSocketSslResumptionNewCb)
  fun h2o_socket_ssl_async_resumption_setup_ctx(ctx : SslCtx)
  fun h2o_socket_ssl_destroy_session_cache_entry(value : H2oIovecT)
  fun h2o_socket_ssl_get_picotls_context(ossl : SslCtx) : StPtlsContextT*
  fun h2o_socket_ssl_get_selected_protocol(sock : H2oSocketT*) : H2oIovecT
  fun h2o_socket_ssl_get_session_cache(ctx : SslCtx) : H2oCacheT
  fun h2o_socket_ssl_handshake(sock : H2oSocketT*, ssl_ctx : SslCtx, server_name : LibC::Char*, handshake_cb : H2oSocketCb)
  fun h2o_socket_ssl_resume_server_handshake(sock : H2oSocketT*, session_data : H2oIovecT)
  fun h2o_socket_ssl_set_picotls_context(ossl : SslCtx, ptls : StPtlsContextT*)
  fun h2o_socket_ssl_set_session_cache(ctx : SslCtx, cache : H2oCacheT)
  fun h2o_socket_write(sock : H2oSocketT*, bufs : H2oIovecT*, bufcnt : LibC::Int, cb : H2oSocketCb)
  fun h2o_socketpool_cancel_connect(req : H2oSocketpoolConnectRequestT)
  fun h2o_socketpool_connect(req : H2oSocketpoolConnectRequestT*, pool : H2oSocketpoolT*, loop : H2oLoopT*, getaddr_receiver : H2oMultithreadReceiverT*, cb : H2oSocketpoolConnectCb, data : Void*)
  fun h2o_socketpool_dispose(pool : H2oSocketpoolT*)
  fun h2o_socketpool_init_by_address(pool : H2oSocketpoolT*, sa : Sockaddr*, salen : SocklenT, is_ssl : LibC::Int, capacity : LibC::Int)
  fun h2o_socketpool_init_by_hostport(pool : H2oSocketpoolT*, host : H2oIovecT, port : Uint16T, is_ssl : LibC::Int, capacity : LibC::Int)
  fun h2o_socketpool_return(pool : H2oSocketpoolT*, sock : H2oSocketT*) : LibC::Int
  fun h2o_socketpool_set_timeout(pool : H2oSocketpoolT*, loop : H2oLoopT*, msec : Uint64T)
  fun h2o_ssl_register_alpn_protocols(ctx : SslCtx, protocols : H2oIovecT*)
  fun h2o_ssl_register_npn_protocols(ctx : SslCtx, protocols : LibC::Char*)
  fun h2o_start_response(req : H2oReqT*, generator : H2oGeneratorT*)
  fun h2o_status_register(pathconf : H2oPathconfT*)
  fun h2o_status_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_str_at_position(buf : LibC::Char*, src : LibC::Char*, src_len : LibC::Int, lineno : LibC::Int, column : LibC::Int) : LibC::Int
  fun h2o_str_stripws(s : LibC::Char*, len : LibC::Int) : H2oIovecT
  fun h2o_strdup(pool : H2oMemPoolT*, s : LibC::Char*, len : LibC::Int) : H2oIovecT
  fun h2o_strdup_shared(pool : H2oMemPoolT*, s : LibC::Char*, len : LibC::Int) : H2oIovecT
  fun h2o_strdup_slashed(pool : H2oMemPoolT*, s : LibC::Char*, len : LibC::Int) : H2oIovecT
  fun h2o_stringify_protocol_version : LibC::Int
  fun h2o_stringify_proxy_header : LibC::Int
  fun h2o_strstr : LibC::Int
  fun h2o_strtosize : LibC::Int
  fun h2o_strtosizefwd : LibC::Int
  fun h2o_throttle_resp_register(pathconf : H2oPathconfT*)
  fun h2o_throttle_resp_register_configurator(conf : H2oGlobalconfT*)
  fun h2o_time2str_log(buf : LibC::Char*, time : TimeT)
  fun h2o_time2str_rfc1123(buf : LibC::Char*, gmt : Tm*)
  fun h2o_time_compute_body_time(req : StH2oReqT*, delta_usec : Int64T*) : LibC::Int
  fun h2o_time_compute_connect_time(req : StH2oReqT*, delta_usec : Int64T*) : LibC::Int
  fun h2o_time_compute_duration(req : StH2oReqT*, delta_usec : Int64T*) : LibC::Int
  fun h2o_time_compute_header_time(req : StH2oReqT*, delta_usec : Int64T*) : LibC::Int
  fun h2o_time_compute_process_time(req : StH2oReqT*, delta_usec : Int64T*) : LibC::Int
  fun h2o_time_compute_request_total_time(req : StH2oReqT*, delta_usec : Int64T*) : LibC::Int
  fun h2o_time_compute_response_time(req : StH2oReqT*, delta_usec : Int64T*) : LibC::Int
  fun h2o_time_parse_rfc1123(s : LibC::Char*, len : LibC::Int, tm : Tm*) : LibC::Int
  fun h2o_timeout__do_dispose(loop : H2oLoopT*, timeout : H2oTimeoutT*)
  fun h2o_timeout__do_init(loop : H2oLoopT*, timeout : H2oTimeoutT*)
  fun h2o_timeout__do_link(loop : H2oLoopT*, timeout : H2oTimeoutT*, entry : H2oTimeoutEntryT*)
  fun h2o_timeout__do_post_callback(loop : H2oLoopT*)
  fun h2o_timeout_dispose(loop : H2oLoopT*, timeout : H2oTimeoutT*)
  fun h2o_timeout_get_wake_at(timeouts : H2oLinklistT*) : Uint64T
  fun h2o_timeout_init(loop : H2oLoopT*, timeout : H2oTimeoutT*, millis : Uint64T)
  fun h2o_timeout_link(loop : H2oLoopT*, timeout : H2oTimeoutT*, entry : H2oTimeoutEntryT*)
  fun h2o_timeout_run(loop : H2oLoopT*, timeout : H2oTimeoutT*, now : Uint64T)
  fun h2o_timeout_unlink(entry : H2oTimeoutEntryT*)
  fun h2o_timeval_is_null(tv : Timeval*) : LibC::Int
  fun h2o_timeval_subtract(from : Timeval*, until : Timeval*) : Int64T
  fun h2o_uri_escape(pool : H2oMemPoolT*, s : LibC::Char*, l : LibC::Int, preserve_chars : LibC::Char*) : H2oIovecT
  fun h2o_url_copy(pool : H2oMemPoolT*, dest : H2oUrlT*, src : H2oUrlT*)
  fun h2o_url_host_is_unix_path(host : H2oIovecT) : LibC::Int
  fun h2o_url_host_to_sun(host : H2oIovecT, sa : SockaddrUn*) : LibC::Char*
  fun h2o_url_hosts_are_equal(url_a : H2oUrlT*, url_b : H2oUrlT*) : LibC::Int
  fun h2o_url_normalize_path(pool : H2oMemPoolT*, path : LibC::Char*, len : LibC::Int, query_at : LibC::Int*, norm_indexes : LibC::Int**) : H2oIovecT
  fun h2o_url_parse(url : LibC::Char*, url_len : LibC::Int, result : H2oUrlT*) : LibC::Int
  fun h2o_url_parse_hostport(s : LibC::Char*, len : LibC::Int, host : H2oIovecT*, port : Uint16T*) : LibC::Char*
  fun h2o_url_parse_relative(url : LibC::Char*, url_len : LibC::Int, result : H2oUrlT*) : LibC::Int
  fun h2o_url_resolve(pool : H2oMemPoolT*, base : H2oUrlT*, relative : H2oUrlT*, dest : H2oUrlT*) : H2oIovecT
  fun h2o_url_resolve_path(base : H2oIovecT*, relative : H2oIovecT*)
  fun h2o_vector__expand(pool : H2oMemPoolT*, vector : H2oVectorT*, element_size : LibC::Int, new_capacity : LibC::Int)

  struct Addrinfo
    ai_flags : LibC::Int
    ai_family : LibC::Int
    ai_socktype : LibC::Int
    ai_protocol : LibC::Int
    ai_addrlen : SocklenT
    ai_addr : Sockaddr*
    ai_canonname : LibC::Char*
    ai_next : Addrinfo*
  end

  struct H2oContextStorageT
    entries : H2oContextStorageItemT*
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct H2oHeadersT
    entries : H2oHeaderT*
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct H2oIovecVectorT
    entries : H2oIovecT*
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct H2oStatusCallbacksT
    entries : H2oStatusHandlerT*
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct H2oVectorT
    entries : Void*
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct InAddr
    s_addr : InAddrT
  end

  struct Sockaddr
    sa_family : SaFamilyT
    sa_data : LibC::Char[14]
  end

  struct SockaddrUn
    sun_family : SaFamilyT
    sun_path : LibC::Char[108]
  end

  struct StH2oAcceptCtxT
    ctx : H2oContextT*
    hosts : H2oHostconfT**
    ssl_ctx : SslCtx
    expect_proxy_line : LibC::Int
    libmemcached_receiver : H2oMultithreadReceiverT*
  end

  struct StH2oBarrierT
    _mutex : PthreadMutexT
    _cond : PthreadCondT
    _count : LibC::Int
  end

  struct StH2oBufferMmapSettingsT
    threshold : UInt64 # LibC::Int
    fn_template : LibC::Char[4096]
  end

  struct StH2oBufferPrototypeT
    allocator : H2oMemRecycleT
    _initial_buf : H2oBufferT
    mmap_settings : H2oBufferMmapSettingsT*
  end

  struct StH2oBufferT
    capacity : UInt64 # LibC::Int
    size : UInt64     # LibC::Int
    bytes : LibC::Char*
    _prototype : H2oBufferPrototypeT*
    _fd : LibC::Int
    _buf : LibC::Char[1]
  end

  struct StH2oCacheKeyT
    vec : H2oIovecT
    hash : H2oCacheHashcodeT
  end

  struct StH2oCacheRefT
    key : H2oIovecT
    keyhash : H2oCacheHashcodeT
    at : Uint64T
    value : H2oIovecT
    _requested_early_update : LibC::Int
    _lru_link : H2oLinklistT
    _age_link : H2oLinklistT
    _refcnt : LibC::Int
  end

  struct StH2oCasperConfT
    capacity_bits : LibC::UInt
    track_all_types : LibC::Int
  end

  struct StH2oCompressArgsT
    min_size : LibC::Int
    gzip : StH2oCompressArgsTGzip
    brotli : StH2oCompressArgsTBrotli
  end

  struct StH2oCompressArgsTBrotli
    quality : LibC::Int
  end

  struct StH2oCompressArgsTGzip
    quality : LibC::Int
  end

  struct StH2oCompressContextT
    name : H2oIovecT
    transform : (StH2oCompressContextT*, H2oIovecT*, LibC::Int, H2oSendStateT, H2oIovecT**, LibC::Int* -> Void)
  end

  struct StH2oConnCallbacksT
    get_sockname : (H2oConnT*, Sockaddr* -> SocklenT)
    get_peername : (H2oConnT*, Sockaddr* -> SocklenT)
    push_path : (H2oReqT*, LibC::Char*, LibC::Int -> Void)
    get_socket : (H2oConnT* -> H2oSocketT*)
    get_debug_state : (H2oReqT*, LibC::Int -> H2oHttp2DebugStateT*)
    log_ : StH2oConnCallbacksTLog
  end

  struct StH2oConnT
    ctx : H2oContextT*
    hosts : H2oHostconfT**
    connected_at : Timeval
    id : Uint64T
    callbacks : H2oConnCallbacksT*
  end

  struct StH2oContextStorageItemT
    dispose : (Void* -> Void)
    data : Void*
  end

  struct StH2oContextT
    loop : H2oLoopT*
    zero_timeout : H2oTimeoutT
    one_sec_timeout : H2oTimeoutT
    hundred_ms_timeout : H2oTimeoutT
    globalconf : H2oGlobalconfT*
    queue : H2oMultithreadQueueT
    receivers : StH2oContextTReceivers
    filecache : H2oFilecacheT
    storage : H2oContextStorageT
    shutdown_requested : LibC::Int
    handshake_timeout : H2oTimeoutT
    http1 : StH2oContextTHttp1
    http2 : StH2oContextTHttp2
    proxy : StH2oContextTProxy
    _module_configs : Void**
    _timestamp_cache : StH2oContextTTimestampCache
    emitted_error_status : Uint64T[10]
    _pathconfs_inited : StH2oContextTPathconfsInited
  end

  struct StH2oContextTHttp1
    req_timeout : H2oTimeoutT
    _conns : H2oLinklistT
  end

  struct StH2oContextTHttp2
    idle_timeout : H2oTimeoutT
    _conns : H2oLinklistT
    graceful_shutdown_timeout : H2oTimeoutT
    _graceful_shutdown_timeout : H2oTimeoutEntryT
    events : StH2oContextTHttp2Events
  end

  struct StH2oContextTHttp2Events
    protocol_level_errors : Uint64T[13]
    read_closed : Uint64T
    write_closed : Uint64T
  end

  struct StH2oContextTPathconfsInited
    entries : H2oPathconfT**
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct StH2oContextTProxy
    client_ctx : H2oHttp1clientCtxT
    io_timeout : H2oTimeoutT
  end

  struct StH2oContextTReceivers
    hostinfo_getaddr : H2oMultithreadReceiverT
  end

  struct StH2oContextTTimestampCache
    uv_now_at : Uint64T
    tv_at : Timeval
    value : H2oTimestampStringT*
  end

  struct StH2oDoublebufferT
    buf : H2oBufferT*
    bytes_inflight : LibC::Int
  end

  struct StH2oEnvconfT
    parent : StH2oEnvconfT*
    unsets : H2oIovecVectorT
    sets : H2oIovecVectorT
  end

  struct StH2oErrordocT
    status : LibC::Int
    url : H2oIovecT
  end

  struct StH2oExpiresArgsT
    mode : LibC::Int
    data : StH2oExpiresArgsTData
  end

  struct StH2oFastcgiConfigVarsT
    io_timeout : Uint64T
    keepalive_timeout : Uint64T
    document_root : H2oIovecT
    send_delegated_uri : LibC::Int
    callbacks : StH2oFastcgiConfigVarsTCallbacks
  end

  struct StH2oFastcgiConfigVarsTCallbacks
    dispose : (H2oFastcgiHandlerT, Void* -> Void)
    data : Void*
  end

  struct StH2oFilecacheRefT
    fd : LibC::Int
    _refcnt : LibC::Int
    _lru : H2oLinklistT
    _path : LibC::Char[1]
  end

  struct StH2oFilereqT
    url_path_len : LibC::Int
    local_path : H2oIovecT
  end

  struct StH2oFilterT
    _config_slot : LibC::Int
    on_context_init : (StH2oFilterT*, H2oContextT* -> Void)
    on_context_dispose : (StH2oFilterT*, H2oContextT* -> Void)
    dispose : (StH2oFilterT* -> Void)
    on_setup_ostream : (StH2oFilterT*, H2oReqT*, H2oOstreamT** -> Void)
  end

  struct StH2oGeneratorT
    proceed : (StH2oGeneratorT*, H2oReqT* -> Void)
    stop : (StH2oGeneratorT*, H2oReqT* -> Void)
  end

  struct StH2oGlobalconfT
    hosts : H2oHostconfT**            # 0 (8)
    configurators : H2oLinklistT      # 8 (8 + 8)
    server_name : H2oIovecT           # 24 (8 + 4 + (4))
    max_request_entity_size : Uint64T # LibC::Int # 40 (4 + (4))
    max_delegations : LibC::UInt      # 48 (4 + (4))
    user : LibC::Char*                # 56 (8)
    handshake_timeout : Uint64T       # 64 (8)
    http1 : StH2oGlobalconfTHttp1     # 72 (8 + 4 + (4) + 8 + 8)
    http2 : StH2oGlobalconfTHttp2     # 104 (64)
    proxy : StH2oGlobalconfTProxy     # 168 (24)
    mimemap : H2oMimemapT             # 192 (8)
    filecache : StH2oGlobalconfTFilecache
    statuses : H2oStatusCallbacksT
    _num_config_slots : Uint64T # LibC::Int
  end

  struct StH2oGlobalconfTFilecache
    capacity : Uint64T # LibC::Int
  end

  struct StH2oGlobalconfTHttp1 # 32
    req_timeout : Uint64T
    upgrade_to_http2 : LibC::Int
    callbacks : H2oProtocolCallbacksT
  end

  struct StH2oGlobalconfTHttp2 # 64
    idle_timeout : Uint64T
    graceful_shutdown_timeout : Uint64T
    max_concurrent_requests_per_connection : Uint64T # LibC::Int
    max_streams_for_priority : Uint64T               # LibC::Int
    latency_optimization : H2oSocketLatencyOptimizationConditionsT
    callbacks : H2oProtocolCallbacksT
  end

  struct StH2oGlobalconfTProxy
    io_timeout : Uint64T
    ssl_ctx : SslCtx
    flags : LibC::UInt
    # preserve_x_forwarded_proto : LibC::UInt
    # preserve_server_header : LibC::UInt
    # emit_x_forwarded_headers : LibC::UInt
    # emit_via_header : LibC::UInt
  end

  struct StH2oHandlerT
    _config_slot : UInt64 # LibC::Int
    on_context_init : (StH2oHandlerT*, H2oContextT* -> Void)
    on_context_dispose : (StH2oHandlerT*, H2oContextT* -> Void)
    dispose : (StH2oHandlerT* -> Void)
    on_req : (StH2oHandlerT*, H2oReqT* -> LibC::Int)
  end

  struct StH2oHeaderT
    name : H2oIovecT*
    orig_name : LibC::Char*
    val : H2oIovecT
  end

  struct StH2oHeadersCommandT
    cmd : LibC::Int
    name : H2oIovecT*
    value : H2oIovecT
  end

  struct StH2oHostconfT
    global : H2oGlobalconfT*
    authority : StH2oHostconfTAuthority
    paths : StH2oHostconfTPaths
    fallback_path : H2oPathconfT
    mimemap : H2oMimemapT
    http2 : StH2oHostconfTHttp2
  end

  struct StH2oHostconfTAuthority
    hostport : H2oIovecT
    host : H2oIovecT
    port : Uint16T
  end

  struct StH2oHostconfTHttp2
    # reprioritize_blocking_assets : LibC::UInt
    # push_preload : LibC::UInt
    flags : UInt32
    casper : H2oCasperConfT
  end

  struct StH2oHostconfTPaths
    entries : H2oPathconfT*
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct StH2oHttp1clientCtxT
    loop : H2oLoopT*
    getaddr_receiver : H2oMultithreadReceiverT*
    io_timeout : H2oTimeoutT*
    websocket_timeout : H2oTimeoutT*
    ssl_ctx : SslCtx
  end

  struct StH2oHttp1clientT
    ctx : H2oHttp1clientCtxT*
    sockpool : StH2oHttp1clientTSockpool
    ssl : StH2oHttp1clientTSsl
    sock : H2oSocketT*
    data : Void*
    informational_cb : H2oHttp1clientInformationalCb
  end

  struct StH2oHttp1clientTSockpool
    pool : H2oSocketpoolT*
    connect_req : H2oSocketpoolConnectRequestT
  end

  struct StH2oHttp1clientTSsl
    server_name : LibC::Char*
  end

  struct StH2oHttp2DebugStateT
    json : H2oIovecVectorT
    conn_flow_in : SsizeT
    conn_flow_out : SsizeT
  end

  struct StH2oIovecT
    base : LibC::Char*
    len : UInt64 # LibC::Int
  end

  struct StH2oLinklistT
    next : StH2oLinklistT*
    prev : StH2oLinklistT*
  end

  struct StH2oLoggerT
    _config_slot : LibC::Int
    on_context_init : (StH2oLoggerT*, H2oContextT* -> Void)
    on_context_dispose : (StH2oLoggerT*, H2oContextT* -> Void)
    dispose : (StH2oLoggerT* -> Void)
    log_access : (StH2oLoggerT*, H2oReqT* -> Void)
  end

  struct StH2oMemPoolSharedEntryT
    refcnt : UInt64 # LibC::Int
    dispose : (Void* -> Void)
    bytes : LibC::Char[1]
  end

  struct StH2oMemPoolT
    chunks : Void*
    chunk_offset : UInt64 # LibC::Int
    shared_refs : Void*
    directs : Void*
  end

  struct StH2oMemRecycleT
    max : UInt64 # LibC::Int
    cnt : UInt64 # LibC::Int
    _link : Void*
  end

  struct StH2oMimeAttributesT
    is_compressible : LibC::Char
    priority : Int32
  end

  struct StH2oMimemapTypeT
    type : H2oMimemapType
    data : StH2oMimemapTypeTData
  end

  struct StH2oMimemapTypeTDataDynamic
    pathconf : H2oPathconfT
  end

  struct StH2oMimemapTypeTDataMime
    mimetype : H2oIovecT
    attr : H2oMimeAttributesT
  end

  struct StH2oMultithreadMessageT
    link : H2oLinklistT
  end

  struct StH2oMultithreadReceiverT
    queue : H2oMultithreadQueueT
    _link : H2oLinklistT
    _messages : H2oLinklistT
    cb : H2oMultithreadReceiverCb
  end

  struct StH2oMultithreadRequestT
    super : H2oMultithreadMessageT
    source : H2oMultithreadReceiverT*
    cb : H2oMultithreadResponseCb
  end

  struct StH2oOstreamT
    next : StH2oOstreamT*
    do_send : (StH2oOstreamT*, H2oReqT*, H2oIovecT*, LibC::Int, H2oSendStateT -> Void)
    stop : (StH2oOstreamT*, H2oReqT* -> Void)
    start_pull : (StH2oOstreamT*, H2oOstreamPullCb -> Void)
  end

  struct StH2oPathconfT
    global : H2oGlobalconfT*
    path : H2oIovecT
    handlers : StH2oPathconfTHandlers
    filters : StH2oPathconfTFilters
    loggers : StH2oPathconfTLoggers
    mimemap : H2oMimemapT
    env : H2oEnvconfT*
    error_log : StH2oPathconfTErrorLog
  end

  struct StH2oPathconfTErrorLog
    emit_request_errors : LibC::UInt
  end

  struct StH2oPathconfTFilters
    entries : H2oFilterT**
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct StH2oPathconfTHandlers
    entries : H2oHandlerT**
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct StH2oPathconfTLoggers
    entries : H2oLoggerT**
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct StH2oProtocolCallbacksT
    request_shutdown : (H2oContextT* -> Void)
    foreach_request : (H2oContextT*, (H2oReqT*, Void* -> LibC::Int), Void* -> LibC::Int)
  end

  struct StH2oProxyConfigVarsT
    io_timeout : Uint64T
    preserve_host : LibC::UInt
    use_proxy_protocol : LibC::UInt
    keepalive_timeout : Uint64T
    websocket : StH2oProxyConfigVarsTWebsocket
    headers_cmds : H2oHeadersCommandT*
    ssl_ctx : SslCtx
  end

  struct StH2oProxyConfigVarsTWebsocket
    enabled : LibC::Int
    timeout : Uint64T
  end

  struct StH2oReqErrorLogT
    module : LibC::Char*
    msg : H2oIovecT
  end

  struct StH2oReqOverridesT
    client_ctx : H2oHttp1clientCtxT*
    socketpool : H2oSocketpoolT*
    hostport : StH2oReqOverridesTHostport
    location_rewrite : StH2oReqOverridesTLocationRewrite
    use_proxy_protocol : LibC::UInt
    headers_cmds : H2oHeadersCommandT*
  end

  struct StH2oReqOverridesTHostport
    host : H2oIovecT
    port : Uint16T
  end

  struct StH2oReqOverridesTLocationRewrite
    match : H2oUrlT*
    path_prefix : H2oIovecT
  end

  struct StH2oReqPrefilterT
    next : StH2oReqPrefilterT*
    on_setup_ostream : (StH2oReqPrefilterT*, H2oReqT*, H2oOstreamT** -> Void)
  end

  struct StH2oReqT
    conn : H2oConnT*
    input : StH2oReqTInput
    hostconf : H2oHostconfT*
    pathconf : H2oPathconfT*
    scheme : H2oUrlSchemeT*
    authority : H2oIovecT
    method : H2oIovecT
    path : H2oIovecT
    query_at : UInt64 # LibC::Int
    path_normalized : H2oIovecT
    norm_indexes : UInt64* # LibC::Int*
    prefilters : H2oReqPrefilterT*
    filereq : H2oFilereqT*
    overrides : H2oReqOverridesT*
    version : LibC::Int
    headers : H2oHeadersT
    entity : H2oIovecT
    processed_at : H2oTimestampT
    timestamps : StH2oReqTTimestamps
    res : H2oResT
    bytes_sent : UInt64 # LibC::Int
    num_reprocessed : LibC::UInt
    num_delegated : LibC::UInt
    env : H2oIovecVectorT
    error_logs : StH2oReqTErrorLogs
    flags : UInt8
    # http1_is_persistent : UInt8
    # res_is_delegated : UInt8
    # bytes_counted_by_ostream : UInt8
    compress_hint : LibC::Char
    upgrade : H2oIovecT
    preferred_chunk_size : UInt64 # LibC::Int
    _generator : H2oGeneratorT*
    _ostr_top : H2oOstreamT*
    _next_filter_index : UInt64 # LibC::Int
    _timeout_entry : H2oTimeoutEntryT
    pool : H2oMemPoolT
  end

  struct StH2oReqTErrorLogs
    entries : H2oReqErrorLogT*
    size : UInt64     # LibC::Int
    capacity : UInt64 # LibC::Int
  end

  struct StH2oReqTInput
    scheme : H2oUrlSchemeT*
    authority : H2oIovecT
    method : H2oIovecT
    path : H2oIovecT
    query_at : UInt64 # LibC::Int
  end

  struct StH2oReqTTimestamps
    request_begin_at : Timeval
    request_body_begin_at : Timeval
    response_start_at : Timeval
    response_end_at : Timeval
  end

  struct StH2oResT
    status : LibC::Int
    reason : LibC::Char*
    content_length : UInt64 # LibC::Int
    headers : H2oHeadersT
    mime_attr : H2oMimeAttributesT*
    original : StH2oResTOriginal
  end

  struct StH2oResTOriginal
    status : LibC::Int
    headers : H2oHeadersT
  end

  struct StH2oSemT
    _mutex : PthreadMutexT
    _cond : PthreadCondT
    _cur : SsizeT
    _capacity : SsizeT
  end

  struct StH2oSlidingCounterT
    average : Uint64T
    prev : StH2oSlidingCounterTPrev
    cur : StH2oSlidingCounterTCur
  end

  struct StH2oSlidingCounterTCur
    start_at : Uint64T
  end

  struct StH2oSlidingCounterTPrev
    sum : Uint64T
    slots : Uint64T[8]
    index : LibC::Int
  end

  struct StH2oSocketExportT
    fd : LibC::Int
    ssl : Void*
    input : H2oBufferT*
  end

  struct StH2oSocketLatencyOptimizationConditionsT
    min_rtt : LibC::UInt
    max_additional_delay : LibC::UInt
    max_cwnd : LibC::UInt
    pad : LibC::UInt
  end

  struct StH2oSocketPeernameT
    len : SocklenT
    addr : Sockaddr
  end

  struct StH2oSocketT
    data : Void*
    ssl : Void*
    input : H2oBufferT*
    bytes_read : UInt64
    bytes_written : UInt64
    on_close : StH2oSocketTOnClose
    _cb : StH2oSocketTCb
    _peername : StH2oSocketPeernameT*
    _latency_optimization : StH2oSocketTLatencyOptimization
  end

  struct StH2oSocketTCb
    read : H2oSocketCb
    write : H2oSocketCb
  end

  struct StH2oSocketTLatencyOptimization
    state : Uint8T
    notsent_is_minimized : Uint8T
    suggested_tls_payload_size : Uint16T
    suggested_write_size : UInt64
  end

  struct StH2oSocketTOnClose
    cb : (Void* -> Void)
    data : Void*
  end

  struct StH2oSocketpoolT
    type : H2oSocketpoolTypeT
    peer : StH2oSocketpoolTPeer
    is_ssl : LibC::Int
    capacity : LibC::Int
    timeout : Uint64T
    _interval_cb : StH2oSocketpoolTIntervalCb
    _shared : StH2oSocketpoolTShared
  end

  struct StH2oSocketpoolTIntervalCb
    loop : H2oLoopT*
    timeout : H2oTimeoutT
    entry : H2oTimeoutEntryT
  end

  struct StH2oSocketpoolTPeer
    host : H2oIovecT
  end

  struct StH2oSocketpoolTShared
    count : LibC::Int
    mutex : PthreadMutexT
    sockets : H2oLinklistT
  end

  struct StH2oStatusHandlerT
    name : H2oIovecT
    init : (-> Void*)
    per_thread : (Void*, H2oContextT* -> Void)
    final : (Void*, H2oGlobalconfT*, H2oReqT* -> H2oIovecT)
  end

  struct StH2oTimeoutEntryT
    registered_at : Uint64T
    cb : H2oTimeoutCb
    _link : H2oLinklistT
  end

  struct StH2oTimeoutT
    timeout : Uint64T
    _link : H2oLinklistT
    _entries : H2oLinklistT
    _backend : StH2oTimeoutBackendPropertiesT
  end

  struct StH2oTimestampStringT
    rfc1123 : LibC::Char[30]
    log : LibC::Char[27]
  end

  struct StH2oTimestampT
    at : Timeval
    str : H2oTimestampStringT*
  end

  struct StH2oTokenT
    buf : H2oIovecT
    http2_static_table_name_index : LibC::Char
    flags : UInt8
    # proxy_should_drop_for_req : UInt8
    # proxy_should_drop_for_res : UInt8
    # is_init_header_special : UInt8
    # http2_should_reject : UInt8
    # copy_for_push_request : UInt8
  end

  struct StH2oUrlSchemeT
    name : H2oIovecT
    default_port : Uint16T
  end

  struct StH2oUrlT
    scheme : H2oUrlSchemeT*
    authority : H2oIovecT
    host : H2oIovecT
    path : H2oIovecT
    _port : Uint16T
  end

  struct Timeval
    tv_sec : X__TimeT
    tv_usec : X__SusecondsT
  end

  struct Tm
    tm_sec : LibC::Int
    tm_min : LibC::Int
    tm_hour : LibC::Int
    tm_mday : LibC::Int
    tm_mon : LibC::Int
    tm_year : LibC::Int
    tm_wday : LibC::Int
    tm_yday : LibC::Int
    tm_isdst : LibC::Int
    tm_gmtoff : LibC::Long
    tm_zone : LibC::Char*
  end

  struct X_IoFile
    _flags : LibC::Int
    _io_read_ptr : LibC::Char*
    _io_read_end : LibC::Char*
    _io_read_base : LibC::Char*
    _io_write_base : LibC::Char*
    _io_write_ptr : LibC::Char*
    _io_write_end : LibC::Char*
    _io_buf_base : LibC::Char*
    _io_buf_end : LibC::Char*
    _io_save_base : LibC::Char*
    _io_backup_base : LibC::Char*
    _io_save_end : LibC::Char*
    _markers : X_IoMarker*
    _chain : X_IoFile*
    _fileno : LibC::Int
    _flags2 : LibC::Int
    _old_offset : X__OffT
    _cur_column : LibC::UShort
    _vtable_offset : LibC::Char
    _shortbuf : LibC::Char[1]
    _lock : X_IoLockT*
    _offset : X__Off64T
    __pad1 : Void*
    __pad2 : Void*
    __pad3 : Void*
    __pad4 : Void*
    __pad5 : LibC::Int
    _mode : LibC::Int
    _unused2 : LibC::Char
  end

  struct X_IoMarker
    _next : X_IoMarker*
    _sbuf : X_IoFile*
    _pos : LibC::Int
  end

  struct X__PthreadCondS
    __g_refs : LibC::UInt[2]
    __g_size : LibC::UInt[2]
    __g1_orig_size : LibC::UInt
    __wrefs : LibC::UInt
    __g_signals : LibC::UInt[2]
  end

  struct X__PthreadInternalList
    __prev : X__PthreadInternalList*
    __next : X__PthreadInternalList*
  end

  struct X__PthreadMutexS
    __lock : LibC::Int
    __count : LibC::UInt
    __owner : LibC::Int
    __nusers : LibC::UInt
    __kind : LibC::Int
    __spins : LibC::Short
    __elision : LibC::Short
    __list : X__PthreadListT
  end

  alias File = X_IoFile
  alias H2oAcceptCtxT = StH2oAcceptCtxT
  alias H2oAccessLogFilehandleT = Void*
  alias H2oBarrierT = StH2oBarrierT
  alias H2oBufferMmapSettingsT = StH2oBufferMmapSettingsT
  alias H2oBufferPrototypeT = StH2oBufferPrototypeT
  alias H2oBufferT = StH2oBufferT
  alias H2oCacheRefT = StH2oCacheRefT
  alias H2oCacheT = Void*
  alias H2oCasperConfT = StH2oCasperConfT
  alias H2oCompressArgsT = StH2oCompressArgsT
  alias H2oCompressContextT = StH2oCompressContextT
  alias H2oConnCallbacksT = StH2oConnCallbacksT
  alias H2oConnT = StH2oConnT
  alias H2oContextStorageItemT = StH2oContextStorageItemT
  alias H2oContextT = StH2oContextT
  alias H2oDoublebufferT = StH2oDoublebufferT
  alias H2oEnvconfT = StH2oEnvconfT
  alias H2oErrordocT = StH2oErrordocT
  alias H2oExpiresArgsT = StH2oExpiresArgsT
  alias H2oFastcgiConfigVarsT = StH2oFastcgiConfigVarsT
  alias H2oFastcgiHandlerT = Void*
  alias H2oFileHandlerT = Void*
  alias H2oFilecacheRefT = StH2oFilecacheRefT
  alias H2oFilecacheT = Void*
  alias H2oFilereqT = StH2oFilereqT
  alias H2oFilterT = StH2oFilterT
  alias H2oGeneratorT = StH2oGeneratorT
  alias H2oGlobalconfT = StH2oGlobalconfT
  alias H2oHandlerT = StH2oHandlerT
  alias H2oHeaderT = StH2oHeaderT
  alias H2oHeadersCommandT = StH2oHeadersCommandT
  alias H2oHostconfT = StH2oHostconfT
  alias H2oHostinfoGetaddrReqT = Void*
  alias H2oHttp1clientCtxT = StH2oHttp1clientCtxT
  alias H2oHttp1clientT = StH2oHttp1clientT
  alias H2oHttp2DebugStateT = StH2oHttp2DebugStateT
  alias H2oIovecT = StH2oIovecT
  alias H2oLinklistT = StH2oLinklistT
  alias H2oLogconfT = Void*
  alias H2oLoggerT = StH2oLoggerT
  alias H2oMemPoolT = StH2oMemPoolT
  alias H2oMemRecycleT = StH2oMemRecycleT
  alias H2oMemcachedContextT = Void*
  alias H2oMemcachedReqT = Void*
  alias H2oMimeAttributesT = StH2oMimeAttributesT
  alias H2oMimemapT = Void*
  alias H2oMimemapTypeT = StH2oMimemapTypeT
  alias H2oMultithreadMessageT = StH2oMultithreadMessageT
  alias H2oMultithreadQueueT = Void*
  alias H2oMultithreadReceiverT = StH2oMultithreadReceiverT
  alias H2oMultithreadRequestT = StH2oMultithreadRequestT
  alias H2oOstreamT = StH2oOstreamT
  alias H2oPathconfT = StH2oPathconfT
  alias H2oProtocolCallbacksT = StH2oProtocolCallbacksT
  alias H2oProxyConfigVarsT = StH2oProxyConfigVarsT
  alias H2oRedirectHandlerT = Void*
  alias H2oReqErrorLogT = StH2oReqErrorLogT
  alias H2oReqOverridesT = StH2oReqOverridesT
  alias H2oReqPrefilterT = StH2oReqPrefilterT
  alias H2oReqT = StH2oReqT
  alias H2oResT = StH2oResT
  alias H2oSemT = StH2oSemT
  alias H2oSendStateT = H2oSendState
  alias H2oSlidingCounterT = StH2oSlidingCounterT
  alias H2oSocketExportT = StH2oSocketExportT
  alias H2oSocketLatencyOptimizationConditionsT = StH2oSocketLatencyOptimizationConditionsT
  alias H2oSocketT = StH2oSocketT
  alias H2oSocketpoolConnectRequestT = Void*
  alias H2oSocketpoolT = StH2oSocketpoolT
  alias H2oSocketpoolTypeT = EnH2oSocketpoolTypeT
  alias H2oStatusHandlerT = StH2oStatusHandlerT
  alias H2oTimeoutEntryT = StH2oTimeoutEntryT
  alias H2oTimeoutT = StH2oTimeoutT
  alias H2oTimestampStringT = StH2oTimestampStringT
  alias H2oTimestampT = StH2oTimestampT
  alias H2oTokenT = StH2oTokenT
  alias H2oUrlSchemeT = StH2oUrlSchemeT
  alias H2oUrlT = StH2oUrlT
  alias SslCtx = Void*

  alias X__PthreadListT = X__PthreadInternalList

  union PthreadAttrT
    __size : LibC::Char[56]
    __align : LibC::Long
  end

  union PthreadCondT
    __data : X__PthreadCondS
    __size : LibC::Char[48]
    __align : LibC::LongLong
  end

  union PthreadMutexT
    __data : X__PthreadMutexS
    __size : LibC::Char[40]
    __align : LibC::Long
  end

  union StH2oConnCallbacksTLog
    callbacks : (H2oReqT* -> H2oIovecT)[1]
  end

  union StH2oExpiresArgsTData
    absolute : LibC::Char*
    max_age : Uint64T
  end

  union StH2oMimemapTypeTData
    mime : StH2oMimemapTypeTDataMime
    dynamic : StH2oMimemapTypeTDataDynamic
  end
end
