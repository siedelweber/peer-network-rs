//! Public provisioning setup on the unchanged protected host wire path.
//! (´[ROOT-rule:observe:credential-store-contract]´)

use super::{OwnedInstance, StandingProfile};
use crate::{Configuration, scram, wire};
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Transport,
    Protocol,
    Server,
    Inventory,
}

#[derive(Debug, PartialEq, Eq)]
enum PublicFrame {
    Parsed,
    Description,
    Boolean(bool),
    Completion,
    Ready,
}

// Fixture-only secret boundary: This host transport witness parses only its public inventory responses.
// Caveat: The protected provisioning response is borrowed only to validate public inventory booleans and protocol completion; the borrow ends at that parse, unexpected fields remain protected, and the framing predicates require a byte slice.
// (´[ROOT-cav:observe:secret-host-credential-inventory-readback]´)
// Justified: Only the admitted public inventory result and completion classes leave the protected response parser.
#[allow(clippy::disallowed_methods)]
fn public_frame(frame: &wire::Frame) -> Result<PublicFrame, Refusal> {
    let bytes = frame.payload.expose_bytes(/* (´[ROOT-cav:observe:secret-host-credential-inventory-readback]´) */);
    match frame.kind {
        b'1' if bytes.is_empty() => Ok(PublicFrame::Parsed),
        b'Z' if bytes == b"I" => Ok(PublicFrame::Ready),
        b'C' if !bytes.is_empty() && bytes.last() == Some(&0) && !bytes[..bytes.len() - 1].contains(&0) => {
            Ok(PublicFrame::Completion)
        }
        // SELECT's sole public boolean column has a fixed text-format description.
        b'T' if bytes == b"\0\x01ok\0\0\0\0\0\0\0\0\0\0\x10\0\x01\xff\xff\xff\xff\0\0" => Ok(PublicFrame::Description),
        b'D' if bytes == b"\0\x01\0\0\0\x01t" => Ok(PublicFrame::Boolean(true)),
        b'D' if bytes == b"\0\x01\0\0\0\x01f" => Ok(PublicFrame::Boolean(false)),
        _ => Err(Refusal::Protocol),
    }
}

struct RawSession {
    socket: wire::Socket,
}

impl RawSession {
    async fn open(instance: &OwnedInstance) -> Result<Self, Refusal> {
        let input = serde_json::to_vec(&serde_json::json!({
            "transport":"unix", "endpoint":instance.root.join(".s.PGSQL.5432"),
            "port":"5432", "user":"credential_public", "database":"postgres",
            "password":"credential_public_setup_password"
        }))
        .unwrap();
        let config = Configuration::acquire(Some("host-secured"), &mut input.as_slice()).map_err(|_| Refusal::Transport)?;
        let socket = tokio::time::timeout(Duration::from_secs(600), async {
            let mut socket = wire::Socket::open(&config).await.map_err(|_| Refusal::Transport)?;
            scram::login(&mut socket, &config).await.map_err(|_| Refusal::Transport)?;
            let mut key = false;
            loop {
                let frame = wire::read(&mut socket).await.map_err(|_| Refusal::Transport)?;
                match frame.kind {
                    // Neither startup parameter bytes nor the real cancellation key
                    // leave protected storage. Inventory reads establish public state.
                    b'S' => {}
                    b'K' if !key && frame.payload.len() == 8 => key = true,
                    b'Z' if key && public_frame(&frame)? == PublicFrame::Ready => break,
                    _ => return Err(Refusal::Protocol),
                }
            }
            Ok(socket)
        })
        .await
        .expect("HANG awaiting credential raw authenticated startup; last state=protected handshake")?;
        for (_, limits) in instance.process_limits() {
            super::core_limits(&limits).expect("raw issuing backend inherits one/one core limits");
        }
        Ok(Self { socket })
    }

    async fn query(&mut self, sql: &str, boolean: bool) -> Result<bool, Refusal> {
        // Every caller supplies only fixed or publicly assembled setup SQL.
        cli_common::emit(&serde_json::json!({"credential_public_statement":sql})).unwrap();
        let mut message = sql.as_bytes().to_vec();
        message.push(0);
        tokio::time::timeout(Duration::from_secs(600), async {
            wire::send(&mut self.socket, b'Q', &message)
                .await
                .map_err(|_| Refusal::Transport)?;
            let mut description = false;
            let mut value = None;
            let mut completion = false;
            let mut error = false;
            loop {
                let frame = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
                if frame.kind == b'E' {
                    error = true;
                    continue;
                }
                // ParameterStatus and diagnostics are not ordinary result data.
                if frame.kind == b'S' || frame.kind == b'N' {
                    return Err(Refusal::Protocol);
                }
                match public_frame(&frame)? {
                    PublicFrame::Description if boolean && !description && value.is_none() && !completion => description = true,
                    PublicFrame::Boolean(actual) if description && value.is_none() && !completion => value = Some(actual),
                    PublicFrame::Completion if !completion => completion = true,
                    PublicFrame::Ready => {
                        if error {
                            return Err(Refusal::Server);
                        }
                        if !completion || (boolean && value.is_none()) || (!boolean && description) {
                            return Err(Refusal::Protocol);
                        }
                        return Ok(value.unwrap_or(true));
                    }
                    _ => return Err(Refusal::Protocol),
                }
            }
        })
        .await
        .expect("HANG awaiting credential raw statement completion; last state=protected response")
    }

    async fn require(&mut self, predicate: &str) -> Result<(), Refusal> {
        let sql = format!("SELECT ({predicate}) IS TRUE AS ok");
        if !self.query(&sql, true).await? {
            return Err(Refusal::Inventory);
        }
        Ok(())
    }

    async fn outer(&mut self) -> Result<(), Refusal> {
        let mut parse = vec![0];
        parse.extend_from_slice(OUTER.as_bytes());
        parse.extend_from_slice(&[0, 0, 1, 0, 0, 0, 25]);
        tokio::time::timeout(Duration::from_secs(600), async {
            wire::send(&mut self.socket, b'P', &parse)
                .await
                .map_err(|_| Refusal::Transport)?;
            wire::send(&mut self.socket, b'S', &[])
                .await
                .map_err(|_| Refusal::Transport)?;
            let parsed = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
            if public_frame(&parsed)? != PublicFrame::Parsed {
                return Err(Refusal::Protocol);
            }
            let ready = wire::read(&mut self.socket).await.map_err(|_| Refusal::Transport)?;
            if public_frame(&ready)? != PublicFrame::Ready {
                return Err(Refusal::Protocol);
            }
            Ok(())
        })
        .await
        .expect("HANG awaiting credential raw public Parse; last state=unnamed statement")
    }

    async fn close(mut self) -> Result<(), Refusal> {
        tokio::time::timeout(Duration::from_secs(600), wire::send(&mut self.socket, b'X', &[]))
            .await
            .expect("HANG awaiting credential raw termination; last state=public terminate")
            .map_err(|_| Refusal::Transport)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Inventory {
    Statements,
    Durations,
    Samples,
    Errors,
    Parameters,
    Trees,
    Statistics,
    OtherLogs,
    Jit,
    Activity,
    CrashReport,
    Modules,
    Explain,
    StatementExtension,
    UnknownFacilities,
    Helper,
    Listings,
    Counters,
    Destinations,
    ConnectionLogs,
    Background,
    Client,
    Plan,
    Core,
    Wal,
    Archive,
    Senders,
    Slots,
    Replicas,
    Titles,
    ClientCustody,
}

const INVENTORY: [Inventory; 31] = [
    Inventory::Statements,
    Inventory::Durations,
    Inventory::Samples,
    Inventory::Errors,
    Inventory::Parameters,
    Inventory::Trees,
    Inventory::Statistics,
    Inventory::OtherLogs,
    Inventory::Jit,
    Inventory::Activity,
    Inventory::CrashReport,
    Inventory::Modules,
    Inventory::Explain,
    Inventory::StatementExtension,
    Inventory::UnknownFacilities,
    Inventory::Helper,
    Inventory::Listings,
    Inventory::Counters,
    Inventory::Destinations,
    Inventory::ConnectionLogs,
    Inventory::Background,
    Inventory::Client,
    Inventory::Plan,
    Inventory::Core,
    Inventory::Wal,
    Inventory::Archive,
    Inventory::Senders,
    Inventory::Slots,
    Inventory::Replicas,
    Inventory::Titles,
    Inventory::ClientCustody,
];

const SUPPRESSIONS: &[(&str, &str)] = &[
    ("log_statement", "none"),
    ("log_min_duration_statement", "-1"),
    ("log_duration", "off"),
    ("log_min_duration_sample", "-1"),
    ("log_statement_sample_rate", "0"),
    ("log_transaction_sample_rate", "0"),
    ("log_min_error_statement", "panic"),
    ("log_min_messages", "panic"),
    ("log_error_verbosity", "terse"),
    ("log_parameter_max_length", "0"),
    ("log_parameter_max_length_on_error", "0"),
    ("debug_print_raw_parse", "off"),
    ("debug_print_parse", "off"),
    ("debug_print_rewritten", "off"),
    ("debug_print_plan", "off"),
    ("log_statement_stats", "off"),
    ("log_parser_stats", "off"),
    ("log_planner_stats", "off"),
    ("log_executor_stats", "off"),
    ("log_lock_waits", "off"),
    ("log_lock_failures", "off"),
    ("log_replication_commands", "off"),
    ("log_temp_files", "-1"),
    ("backtrace_functions", ""),
    ("track_activities", "off"),
    ("client_min_messages", "error"),
    ("plan_cache_mode", "force_generic_plan"),
];

const SETTING_NAMES: &str = "DateStyle,IntervalStyle,TimeZone,allow_alter_system,allow_in_place_tablespaces,allow_system_table_mods,application_name,archive_cleanup_command,archive_command,archive_library,archive_mode,archive_timeout,array_nulls,authentication_timeout,autovacuum,autovacuum_analyze_scale_factor,autovacuum_analyze_score_weight,autovacuum_analyze_threshold,autovacuum_freeze_max_age,autovacuum_freeze_score_weight,autovacuum_max_parallel_workers,autovacuum_max_workers,autovacuum_multixact_freeze_max_age,autovacuum_multixact_freeze_score_weight,autovacuum_naptime,autovacuum_vacuum_cost_delay,autovacuum_vacuum_cost_limit,autovacuum_vacuum_insert_scale_factor,autovacuum_vacuum_insert_score_weight,autovacuum_vacuum_insert_threshold,autovacuum_vacuum_max_threshold,autovacuum_vacuum_scale_factor,autovacuum_vacuum_score_weight,autovacuum_vacuum_threshold,autovacuum_work_mem,autovacuum_worker_slots,backend_flush_after,backslash_quote,backtrace_functions,bgwriter_delay,bgwriter_flush_after,bgwriter_lru_maxpages,bgwriter_lru_multiplier,block_size,bonjour,bonjour_name,bytea_output,check_function_bodies,checkpoint_completion_target,checkpoint_flush_after,checkpoint_timeout,checkpoint_warning,client_connection_check_interval,client_encoding,client_min_messages,cluster_name,commit_delay,commit_siblings,commit_timestamp_buffers,compute_query_id,config_file,constraint_exclusion,cpu_index_tuple_cost,cpu_operator_cost,cpu_tuple_cost,createrole_self_grant,cursor_tuple_fraction,data_checksums,data_directory,data_directory_mode,data_sync_retry,deadlock_timeout,debug_assertions,debug_discard_caches,debug_exec_backend,debug_io_direct,debug_logical_replication_streaming,debug_parallel_query,debug_pretty_print,debug_print_parse,debug_print_plan,debug_print_raw_parse,debug_print_rewritten,default_statistics_target,default_table_access_method,default_tablespace,default_text_search_config,default_toast_compression,default_transaction_deferrable,default_transaction_isolation,default_transaction_read_only,dynamic_library_path,dynamic_shared_memory_type,effective_cache_size,effective_io_concurrency,effective_wal_level,enable_async_append,enable_bitmapscan,enable_distinct_reordering,enable_eager_aggregate,enable_gathermerge,enable_group_by_reordering,enable_hashagg,enable_hashjoin,enable_incremental_sort,enable_indexonlyscan,enable_indexscan,enable_material,enable_memoize,enable_mergejoin,enable_nestloop,enable_parallel_append,enable_parallel_hash,enable_partition_pruning,enable_partitionwise_aggregate,enable_partitionwise_join,enable_presorted_aggregate,enable_self_join_elimination,enable_seqscan,enable_sort,enable_tidscan,event_source,event_triggers,exit_on_error,extension_control_path,external_pid_file,extra_float_digits,file_copy_method,file_extend_method,from_collapse_limit,fsync,full_page_writes,geqo,geqo_effort,geqo_generations,geqo_pool_size,geqo_seed,geqo_selection_bias,geqo_threshold,gin_fuzzy_search_limit,gin_pending_list_limit,gss_accept_delegation,hash_mem_multiplier,hba_file,hosts_file,hot_standby,hot_standby_feedback,huge_page_size,huge_pages,huge_pages_status,icu_validation_level,ident_file,idle_in_transaction_session_timeout,idle_replication_slot_timeout,idle_session_timeout,ignore_checksum_failure,ignore_invalid_pages,ignore_system_indexes,in_hot_standby,integer_datetimes,io_combine_limit,io_max_combine_limit,io_max_concurrency,io_max_workers,io_method,io_min_workers,io_worker_idle_timeout,io_worker_launch_interval,jit,jit_above_cost,jit_debugging_support,jit_dump_bitcode,jit_expressions,jit_inline_above_cost,jit_optimize_above_cost,jit_profiling_support,jit_provider,jit_tuple_deforming,join_collapse_limit,krb_caseins_users,krb_server_keyfile,lc_messages,lc_monetary,lc_numeric,lc_time,listen_addresses,lo_compat_privileges,local_preload_libraries,lock_timeout,log_autoanalyze_min_duration,log_autovacuum_min_duration,log_checkpoints,log_connections,log_destination,log_directory,log_disconnections,log_duration,log_error_verbosity,log_executor_stats,log_file_mode,log_filename,log_hostname,log_line_prefix,log_lock_failures,log_lock_waits,log_min_duration_sample,log_min_duration_statement,log_min_error_statement,log_min_messages,log_parameter_max_length,log_parameter_max_length_on_error,log_parser_stats,log_planner_stats,log_recovery_conflict_waits,log_replication_commands,log_rotation_age,log_rotation_size,log_startup_progress_interval,log_statement,log_statement_sample_rate,log_statement_stats,log_temp_files,log_timezone,log_transaction_sample_rate,log_truncate_on_rotation,logging_collector,logical_decoding_work_mem,maintenance_io_concurrency,maintenance_work_mem,max_active_replication_origins,max_connections,max_files_per_process,max_function_args,max_identifier_length,max_index_keys,max_locks_per_transaction,max_logical_replication_workers,max_notify_queue_pages,max_parallel_apply_workers_per_subscription,max_parallel_maintenance_workers,max_parallel_workers,max_parallel_workers_per_gather,max_pred_locks_per_page,max_pred_locks_per_relation,max_pred_locks_per_transaction,max_prepared_transactions,max_repack_replication_slots,max_replication_slots,max_slot_wal_keep_size,max_stack_depth,max_standby_archive_delay,max_standby_streaming_delay,max_sync_workers_per_subscription,max_wal_senders,max_wal_size,max_worker_processes,md5_password_warnings,min_dynamic_shared_memory,min_eager_agg_group_size,min_parallel_index_scan_size,min_parallel_table_scan_size,min_wal_size,multixact_member_buffers,multixact_offset_buffers,notify_buffers,num_os_semaphores,oauth_validator_libraries,output_plugin_libraries,parallel_leader_participation,parallel_setup_cost,parallel_tuple_cost,password_encryption,password_expiration_warning_threshold,plan_cache_mode,plpgsql.check_asserts,plpgsql.extra_errors,plpgsql.extra_warnings,plpgsql.print_strict_params,plpgsql.variable_conflict,port,post_auth_delay,pre_auth_delay,primary_conninfo,primary_slot_name,quote_all_identifiers,random_page_cost,recovery_end_command,recovery_init_sync_method,recovery_min_apply_delay,recovery_prefetch,recovery_target,recovery_target_action,recovery_target_inclusive,recovery_target_lsn,recovery_target_name,recovery_target_time,recovery_target_timeline,recovery_target_xid,recursive_worktable_factor,remove_temp_files_after_crash,reserved_connections,restart_after_crash,restore_command,restrict_nonsystem_relation_kind,row_security,scram_iterations,search_path,segment_size,send_abort_for_crash,send_abort_for_kill,seq_page_cost,serializable_buffers,server_encoding,server_version,server_version_num,session_preload_libraries,session_replication_role,shared_buffers,shared_memory_size,shared_memory_size_in_huge_pages,shared_memory_type,shared_preload_libraries,ssl,ssl_ca_file,ssl_cert_file,ssl_ciphers,ssl_crl_dir,ssl_crl_file,ssl_dh_params_file,ssl_groups,ssl_key_file,ssl_library,ssl_max_protocol_version,ssl_min_protocol_version,ssl_passphrase_command,ssl_passphrase_command_supports_reload,ssl_prefer_server_ciphers,ssl_sni,ssl_tls13_ciphers,standard_conforming_strings,statement_timeout,stats_fetch_consistency,subtransaction_buffers,summarize_wal,superuser_reserved_connections,sync_replication_slots,synchronize_seqscans,synchronized_standby_slots,synchronous_commit,synchronous_standby_names,syslog_facility,syslog_ident,syslog_sequence_numbers,syslog_split_messages,tcp_keepalives_count,tcp_keepalives_idle,tcp_keepalives_interval,tcp_user_timeout,temp_buffers,temp_file_limit,temp_tablespaces,timezone_abbreviations,timing_clock_source,trace_connection_negotiation,trace_notify,trace_sort,track_activities,track_activity_query_size,track_commit_timestamp,track_cost_delay_timing,track_counts,track_functions,track_io_timing,track_wal_io_timing,transaction_buffers,transaction_deferrable,transaction_isolation,transaction_read_only,transaction_timeout,transform_null_equals,unix_socket_directories,unix_socket_group,unix_socket_permissions,update_process_title,vacuum_buffer_usage_limit,vacuum_cost_delay,vacuum_cost_limit,vacuum_cost_page_dirty,vacuum_cost_page_hit,vacuum_cost_page_miss,vacuum_failsafe_age,vacuum_freeze_min_age,vacuum_freeze_table_age,vacuum_max_eager_freeze_failure_rate,vacuum_multixact_failsafe_age,vacuum_multixact_freeze_min_age,vacuum_multixact_freeze_table_age,vacuum_truncate,wal_block_size,wal_buffers,wal_compression,wal_consistency_checking,wal_decode_buffer_size,wal_init_zero,wal_keep_size,wal_level,wal_log_hints,wal_receiver_create_temp_slot,wal_receiver_status_interval,wal_receiver_timeout,wal_recycle,wal_retrieve_retry_interval,wal_segment_size,wal_sender_shutdown_timeout,wal_sender_timeout,wal_skip_threshold,wal_summary_keep_time,wal_sync_method,wal_writer_delay,wal_writer_flush_after,work_mem,xmlbinary,xmloption,zero_damaged_pages";

const VIEW_NAMES: &str = "pg_cursors,pg_prepared_statements,pg_prepared_xacts,pg_replication_origin_status,pg_stat_activity,pg_stat_all_indexes,pg_stat_all_tables,pg_stat_archiver,pg_stat_autovacuum_scores,pg_stat_bgwriter,pg_stat_checkpointer,pg_stat_database,pg_stat_database_conflicts,pg_stat_gssapi,pg_stat_io,pg_stat_lock,pg_stat_progress_analyze,pg_stat_progress_basebackup,pg_stat_progress_cluster,pg_stat_progress_copy,pg_stat_progress_create_index,pg_stat_progress_repack,pg_stat_progress_vacuum,pg_stat_recovery,pg_stat_recovery_prefetch,pg_stat_replication,pg_stat_replication_slots,pg_stat_slru,pg_stat_ssl,pg_stat_subscription,pg_stat_subscription_stats,pg_stat_sys_indexes,pg_stat_sys_tables,pg_stat_user_functions,pg_stat_user_indexes,pg_stat_user_tables,pg_stat_wal,pg_stat_wal_receiver,pg_stat_xact_all_tables,pg_stat_xact_sys_tables,pg_stat_xact_user_functions,pg_stat_xact_user_tables,pg_statio_all_indexes,pg_statio_all_sequences,pg_statio_all_tables,pg_statio_sys_indexes,pg_statio_sys_sequences,pg_statio_sys_tables,pg_statio_user_indexes,pg_statio_user_sequences,pg_statio_user_tables,pg_stats,pg_stats_ext,pg_stats_ext_exprs";

const EXTENSION_NAMES: &str = "amcheck:1.5,autoinc:1.0,bloom:1.0,btree_gin:1.4,btree_gist:1.9,citext:1.8,cube:1.5,dblink:1.2,dict_int:1.0,dict_xsyn:1.0,earthdistance:1.2,file_fdw:1.0,fuzzystrmatch:1.2,hstore:1.8,insert_username:1.0,intagg:1.1,intarray:1.5,isn:1.3,lo:1.2,ltree:1.3,moddatetime:1.0,pageinspect:1.13,pg_buffercache:1.7,pg_freespacemap:1.3,pg_logicalinspect:1.0,pg_prewarm:1.2,pg_stash_advice:1.0,pg_stat_statements:1.13,pg_surgery:1.0,pg_trgm:1.6,pg_visibility:1.2,pg_walinspect:1.1,pgcrypto:1.4,pgrowlocks:1.2,pgstattuple:1.5,plpgsql:1.0,postgres_fdw:1.3,refint:1.0,seg:1.4,sslinfo:1.2,tablefunc:1.0,tcn:1.0,tsm_system_rows:1.0,tsm_system_time:1.0,unaccent:1.1";

const HELPER_BODY: &str = r"BEGIN
IF $1 IS NULL OR pg_catalog.octet_length($1) <> 135 OR $1 !~ '^SCRAM-SHA-256[$]600000:[A-Za-z0-9+/]{22}==[$][A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$' THEN
RAISE EXCEPTION USING MESSAGE = 'credential framing refused', ERRCODE = '22023';
END IF;
EXECUTE 'ALTER ROLE credential_target PASSWORD ' || pg_catalog.quote_literal($1);
END";
const OUTER: &str = "SELECT credential_fixture.provision($1::text)";

fn literal(public: &str) -> String {
    format!("'{}'", public.replace('\'', "''"))
}

fn setting(name: &str, expected: &str) -> String {
    format!("current_setting({})={}", literal(name), literal(expected))
}

impl Inventory {
    fn recorded(self) -> String {
        let values: &[(&str, &str)] = match self {
            Self::Trees => &[("debug_pretty_print", "on")],
            Self::Activity => &[("track_activity_query_size", "1024")],
            Self::Counters => &[("compute_query_id", "auto")],
            Self::Destinations => &[
                ("log_directory", "log"),
                ("log_filename", "postgresql-%Y-%m-%d_%H%M%S.log"),
                ("log_file_mode", "0600"),
                ("log_rotation_age", "1440"),
                ("log_rotation_size", "10240"),
                ("log_truncate_on_rotation", "off"),
                ("syslog_facility", "local0"),
                ("syslog_ident", "postgres"),
                ("syslog_sequence_numbers", "on"),
                ("syslog_split_messages", "on"),
            ],
            _ => &[],
        };
        values
            .iter()
            .map(|(name, value)| {
                format!(
                    "(SELECT setting FROM pg_settings WHERE name={})={}",
                    literal(name),
                    literal(value)
                )
            })
            .collect::<Vec<_>>()
            .join(" AND ")
    }
    fn predicate(self) -> String {
        let group: &[(&str,&str)] = match self {
            Self::Statements => &SUPPRESSIONS[0..1],
            Self::Durations => &SUPPRESSIONS[1..3],
            Self::Samples => &SUPPRESSIONS[3..6],
            Self::Errors => &SUPPRESSIONS[6..9],
            Self::Parameters => &SUPPRESSIONS[9..11],
            Self::Trees => &SUPPRESSIONS[11..15],
            Self::Statistics => &SUPPRESSIONS[15..19],
            Self::OtherLogs => &SUPPRESSIONS[19..24],
            Self::Jit => &[("jit_dump_bitcode","off"),("jit_debugging_support","off")],
            Self::Activity | Self::CrashReport => &[("track_activities","off")],
            Self::Modules => return "(SELECT count(*)=1 AND bool_and(module_name='plpgsql' AND version='19rc1') FROM pg_get_loaded_modules()) AND current_setting('shared_preload_libraries')='' AND current_setting('session_preload_libraries')='' AND current_setting('local_preload_libraries')='' AND (SELECT count(*)=1 AND bool_and(extname='plpgsql' AND extversion='1.0') FROM pg_extension)".into(),
            Self::Explain => return "NOT EXISTS (SELECT FROM pg_settings WHERE name LIKE 'auto_explain.%')".into(),
            Self::StatementExtension => return "NOT EXISTS (SELECT FROM pg_settings WHERE name LIKE 'pg_stat_statements.%') AND to_regclass('pg_stat_statements') IS NULL".into(),
            Self::UnknownFacilities => return format!("(SELECT string_agg(name,',' ORDER BY name) FROM pg_settings)={} AND (SELECT string_agg(name || ':' || default_version,',' ORDER BY name) FROM pg_available_extensions)={}",literal(SETTING_NAMES),literal(EXTENSION_NAMES)),
            Self::Helper => return format!("(SELECT count(*)=1 AND bool_and(p.prosrc={} AND p.provolatile='v' AND NOT p.prosecdef AND NOT p.proisstrict AND p.proparallel='u' AND p.pronargs=1 AND p.pronargdefaults=0 AND p.proargtypes='25'::oidvector AND p.prorettype='void'::regtype AND p.proconfig=ARRAY['search_path=pg_catalog'] AND l.lanname='plpgsql' AND NOT EXISTS (SELECT FROM aclexplode(p.proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='credential_fixture' AND p.proname='provision') AND current_setting('plpgsql.print_strict_params')='off'",literal(HELPER_BODY)),
            Self::Listings => return "NOT EXISTS (SELECT FROM pg_prepared_statements) AND NOT EXISTS (SELECT FROM pg_cursors)".into(),
            Self::Counters => return format!("NOT EXISTS (SELECT FROM pg_prepared_xacts) AND (SELECT string_agg(viewname,',' ORDER BY viewname) FROM pg_views WHERE schemaname='pg_catalog' AND (viewname LIKE '%stat%' OR viewname LIKE '%cursor%' OR viewname LIKE '%prepared%'))={}",literal(VIEW_NAMES)),
            Self::Destinations => &[("log_destination","stderr"),("logging_collector","off")],
            Self::ConnectionLogs => &[("log_connections",""),("log_disconnections","off"),("log_hostname","off"),("log_line_prefix","")],
            Self::Background => &[("log_checkpoints","on"),("log_autoanalyze_min_duration","10min"),("log_autovacuum_min_duration","10min"),("log_recovery_conflict_waits","off"),("log_startup_progress_interval","10s")],
            Self::Client => &[("client_min_messages","error")],
            Self::Plan => &[("plan_cache_mode","force_generic_plan")],
            // These two rows combine this query with the owned-instance read-back
            // and the source/exit census; they are not SQL proofs of host custody.
            Self::Core | Self::ClientCustody => &[("server_version_num","190000")],
            Self::Wal => return "current_setting('wal_level')='minimal' AND current_setting('effective_wal_level')='minimal' AND NOT EXISTS (SELECT FROM pg_tablespace WHERE pg_tablespace_location(oid)<>'')".into(),
            Self::Archive => return "current_setting('archive_mode')='off' AND current_setting('archive_command')='(disabled)' AND current_setting('archive_library')='' AND (SELECT count(*)=1 AND bool_and(setting='' AND applied AND error IS NULL) FROM pg_file_settings WHERE name='archive_command')".into(),
            Self::Senders => return "current_setting('max_wal_senders')='0' AND NOT EXISTS (SELECT FROM pg_stat_replication)".into(),
            Self::Slots => return "current_setting('max_replication_slots')='0' AND NOT EXISTS (SELECT FROM pg_replication_slots)".into(),
            Self::Replicas => return "NOT pg_is_in_recovery() AND NOT EXISTS (SELECT FROM pg_subscription) AND NOT EXISTS (SELECT FROM pg_stat_wal_receiver)".into(),
            Self::Titles => &[("update_process_title","on")],
        };
        group
            .iter()
            .map(|(name, value)| setting(name, value))
            .collect::<Vec<_>>()
            .join(" AND ")
    }
}

async fn prepare(session: &mut RawSession) -> Result<(), Refusal> {
    for (name, value) in SUPPRESSIONS {
        session.query(&format!("SET {name}={}", literal(value)), false).await?;
    }
    session.query("LOAD 'plpgsql'", false).await?;
    session.query("CREATE SCHEMA credential_fixture", false).await?;
    session
        .query("REVOKE ALL ON SCHEMA credential_fixture FROM PUBLIC", false)
        .await?;
    session.query("CREATE ROLE credential_target NOLOGIN", false).await?;
    session.query(&format!("CREATE FUNCTION credential_fixture.provision(text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER PARALLEL UNSAFE SET search_path=pg_catalog AS {}",literal(HELPER_BODY)),false).await?;
    session
        .query("REVOKE ALL ON FUNCTION credential_fixture.provision(text) FROM PUBLIC", false)
        .await?;
    Ok(())
}

async fn inventory(session: &mut RawSession, injected: Option<Inventory>) -> Result<(), Refusal> {
    for row in INVENTORY {
        let predicate = if injected == Some(row) {
            "false".into()
        } else {
            let predicate = row.predicate();
            let recorded = row.recorded();
            if recorded.is_empty() {
                predicate
            } else {
                format!("({predicate}) AND ({recorded})")
            }
        };
        session.require(&predicate).await?;
        cli_common::emit(&serde_json::json!({"credential_inventory":format!("{row:?}"),"confirmed":true})).unwrap();
    }
    Ok(())
}

/// Protected inventory parsing admits only the fixed public boolean row and completion shapes; unexpected, truncated and extra fields refuse without returning their contents.
/// ´claim:host:credential-raw-public-facts´
/// ´test:unit:public-facts´
#[test]
fn public_facts() {
    for (kind, bytes, expected) in [
        (b'D', b"\0\x01\0\0\0\x01t".as_slice(), Ok(PublicFrame::Boolean(true))),
        (b'D', b"\0\x01\0\0\0\x01f".as_slice(), Ok(PublicFrame::Boolean(false))),
        (b'Z', b"I".as_slice(), Ok(PublicFrame::Ready)),
        (b'C', b"SET\0".as_slice(), Ok(PublicFrame::Completion)),
        (b'D', b"\0\x01\0\0\0\x05other".as_slice(), Err(Refusal::Protocol)),
        (b'D', b"\0\x01\0\0\0\x01tX".as_slice(), Err(Refusal::Protocol)),
        (b'D', b"\0\x01\0\0\0".as_slice(), Err(Refusal::Protocol)),
        (b'Z', b"T".as_slice(), Err(Refusal::Protocol)),
        (b'E', b"public diagnostic".as_slice(), Err(Refusal::Protocol)),
        (b'K', b"public!!".as_slice(), Err(Refusal::Protocol)),
    ] {
        let frame = wire::Frame {
            kind,
            payload: crate::secret::Buffer::from_bytes(bytes).unwrap(),
        };
        assert_eq!(public_frame(&frame), expected, "assigned public fact framing");
    }
}

/// The protected raw session authenticates with public setup material on both owned standing profiles, suppresses and reads the closed inventory in that backend, pins helper source and attributes, and refuses changed parameter and helper states. No generated credential, helper execution, sentinel, acceptance or installation property is exercised.
/// ´claim:host:credential-raw-inventory´
/// ´test:unit:raw-inventory´
#[test]
fn raw_inventory() {
    let programs = super::server_programs(&std::path::PathBuf::from(
        std::env::var_os("PN_POSTGRESQL_BIN").expect("registered server location"),
    ))
    .unwrap();
    let target = std::fs::read_to_string(
        pn_testkit::runtime_path(pn_testkit::RuntimePath::Workspace("packages/host/postgresql-target.txt")).unwrap(),
    )
    .unwrap();
    let version = std::process::Command::new(&programs[0]).arg("--version").output().unwrap();
    assert!(version.status.success());
    super::server_version(std::str::from_utf8(&version.stdout).unwrap(), &target).unwrap();
    let interpreter = std::path::PathBuf::from(std::env::var_os("PN_TEST_PYTHON").expect("registered interpreter"));
    super::core_policy(
        &std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap(),
        &std::fs::read_to_string("/proc/sys/kernel/core_pattern").unwrap(),
    )
    .unwrap();
    super::lower_core_limit(&interpreter);
    super::core_limits(&std::fs::read_to_string("/proc/self/limits").unwrap()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for (index, profile) in [StandingProfile::Statement, StandingProfile::Stages].into_iter().enumerate() {
        let root = std::env::temp_dir().join(format!("credential-raw-{}-{index}", std::process::id()));
        let mut instance = OwnedInstance::start(&programs, root.clone(), profile);
        runtime.block_on(async {
            let session = super::admitted_connection(&instance).await.unwrap();
            drop(session);
            let mut raw = RawSession::open(&instance).await.expect("raw host authentication");
            raw.require("current_setting('server_version_num')='190000'").await.unwrap();
            for (name, expected) in profile.settings() {
                if name != "archive_command" {
                    raw.require(&setting(name, expected))
                        .await
                        .expect("raw standing state precedes suppressions");
                }
            }
            prepare(&mut raw).await.expect("public helper setup");
            inventory(&mut raw, None)
                .await
                .expect("complete inventory confirmed in issuing session");
            for (name, correct) in [
                ("log_parameter_max_length", "0"),
                ("log_parameter_max_length_on_error", "0"),
                ("plan_cache_mode", "force_generic_plan"),
            ] {
                let wrong = if name == "plan_cache_mode" {
                    "force_custom_plan"
                } else {
                    "-1"
                };
                raw.query(&format!("SET {name}={}", literal(wrong)), false).await.unwrap();
                assert_eq!(
                    raw.require(&setting(name, correct)).await,
                    Err(Refusal::Inventory),
                    "changed parameter or plan refuses: {name}"
                );
                raw.query(&format!("SET {name}={}", literal(correct)), false).await.unwrap();
            }
            for (change, restore) in [
                ("STABLE", "VOLATILE"),
                ("SECURITY DEFINER", "SECURITY INVOKER"),
                ("SET search_path=public", "SET search_path=pg_catalog"),
            ] {
                raw.query(&format!("ALTER FUNCTION credential_fixture.provision(text) {change}"), false)
                    .await
                    .unwrap();
                assert_eq!(
                    raw.require(&Inventory::Helper.predicate()).await,
                    Err(Refusal::Inventory),
                    "changed helper attributes refuse: {change}"
                );
                raw.query(&format!("ALTER FUNCTION credential_fixture.provision(text) {restore}"), false)
                    .await
                    .unwrap();
            }
            inventory(&mut raw, None)
                .await
                .expect("restored inventory confirmed before later input");
            for row in INVENTORY {
                assert_eq!(
                    inventory(&mut raw, Some(row)).await,
                    Err(Refusal::Inventory),
                    "assigned inventory row refusal: {row:?}"
                );
            }
            let changed=HELPER_BODY.replace("credential_target", "other_target");
            raw.query(&format!("CREATE OR REPLACE FUNCTION credential_fixture.provision(text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER PARALLEL UNSAFE SET search_path=pg_catalog AS {}",literal(&changed)),false).await.unwrap();
            assert_eq!(raw.require(&Inventory::Helper.predicate()).await,Err(Refusal::Inventory),"changed stored helper source refuses");
            raw.query(&format!("CREATE OR REPLACE FUNCTION credential_fixture.provision(text) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER PARALLEL UNSAFE SET search_path=pg_catalog AS {}",literal(HELPER_BODY)),false).await.unwrap();
            raw.require(&Inventory::Helper.predicate()).await.unwrap();
            assert_eq!(raw.require("missing_public_column").await,Err(Refusal::Server),"failed inventory read-back refuses without diagnostics");
            raw.outer().await.expect("fixed unnamed public Parse admitted without Bind");
            raw.query("LOAD 'auto_explain'",false).await.unwrap();
            assert_eq!(raw.require(&Inventory::Modules.predicate()).await,Err(Refusal::Inventory),"changed loaded module roster refuses");
            raw.close().await.unwrap();
        });
        instance.finish();
        assert!(!root.exists(), "raw instance removed after shutdown");
    }
}
